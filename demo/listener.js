import { parse_ipaddr, Ip6 } from './ipaddr.js';
import { ConnViewer } from './conn-view.js';

// Generate a certificate to represent us
const day_in_ms = 24 * 60 * 60 * 1000;
const year_in_ms = 365 * day_in_ms;
const cert = await RTCPeerConnection.generateCertificate({
	name: 'ECDSA',
	namedCurve: 'P-256',
	expires: Date.now() + year_in_ms,
	hash: 'SHA-256'
});

// Share a common config between gather and outgoing connections
const config = {
	iceTransportPolicy: 'relay',
	iceServers: [{urls: 'turn:stun.evan-brass.net', username: 'guest', credential: 'password'}],
	certificates: [cert]
};

// Use a partially negotiated RTCPeerConnection as if it were an ICEGatherer
const gatherer = new RTCPeerConnection(config);
gatherer.createDataChannel('');

// Mung the ICE credentials:
const ice_ufrag = 'gather';
const ice_pwd = 'the/ice/password/constant';
const offer = await gatherer.createOffer();
offer.sdp = offer.sdp
	.replace(/a=ice-ufrag:.+/img, 'a=ice-ufrag:' + ice_ufrag)
	.replace(/a=ice-pwd:.+/img, 'a=ice-pwd:' + ice_pwd);
await gatherer.setLocalDescription(offer);

// Pull out our certificate fingerprint:
let fingerprint; {
	const {1: hex} = /a=fingerprint:sha-256 ([0-9a-f]{2}(:[0-9a-f]{2}){31})/img.exec(offer.sdp);
	fingerprint = hex.split(':').map(s => parseInt(s, 16));
	console.assert(fingerprint.length == 32);
}

// Wait for ICE gathering to complete
while (gatherer.iceGatheringState != 'complete') await new Promise(res => gatherer.addEventListener('icegatheringstatechange', res, {once: true}));

// Pull out the relay candidates
let candidates = []; {
	for (const {1: address, 2: port_str} of gatherer.localDescription.sdp.matchAll(/a=candidate:.+ ([^ ]+) ([0-9]+) typ relay/img)) {
		const ip = parse_ipaddr(address).mapped();
		if (!(ip instanceof Ip6)) continue; // Only keep ip6 candidates
		const port = parseInt(port_str);
		candidates.push({ ip, port });
	}
}

// Concate the info we need together
let address; {
	const buffer = new Uint8Array(32 + 9*2*candidates.length);
	// First 32 bytes are the fingerprint
	buffer.set(fingerprint);

	const view = new DataView(buffer.buffer, 32);
	for (let i = 0, j = -2; i < candidates.length; ++i) {
		const {ip, port} = candidates[i];
		for (const s of ip) view.setUint16(j += 2, s);
		view.setUint16(j += 2, port);
	}
	address = btoa(String.fromCharCode(...buffer));
}

// Put the address into a sharable anchor tag
const anchor = document.getElementById('address');
anchor.innerText = address;
const href = new URL(document.location);
href.hash = address;
anchor.href = href;


function sdp(fingerprint, ice_ufrag, setup, candidates) {
	return [
		'v=0',
		'o=swbrd 42 0 IN IP4 0.0.0.0',
		's=-',
		't=0 0',
		'a=group:BUNDLE dc',
		`a=fingerprint:sha-256 ${fingerprint}`,
		`a=ice-ufrag:${ice_ufrag}`,
		`a=ice-pwd:${ice_pwd}`,
		'm=application 42 UDP/DTLS/SCTP webrtc-datachannel',
		'c=IN IP4 0.0.0.0',
		'a=mid:dc',
		...candidates,
		`a=setup:${setup}`,
		'a=sctp-port:5000',
		'' // Load bearing newline
	].join('\n')
}

// Check our hash for an address and connect to it
if (document.location.hash.length > 2) try {
	const buffer = new Uint8Array(
		Array.from(atob(document.location.hash.slice(1)), s => s.charCodeAt(0))
	);
	const fingerprint = buffer.subarray(0, 32).reduce(
		// Hex encode the fingerprint
		(a, v, i) => a + (i ? ':' : '') + v.toString(16).padStart(2, '0'),
		''
	);
	const candidates = [];
	const view = new DataView(buffer.buffer, 30);
	for (let i = 0; i + 2 < view.byteLength;) {
		const ip = Array.from({length: 8}, () => view.getUint16(i += 2).toString(16)).join(':');
		const port = view.getUint16(i += 2);
		candidates.push(`a=candidate:foundation 1 udp 42 ${ip} ${port} typ relay raddr :: rport 0`);
	}

	const outgoing = new RTCPeerConnection(config);
	await outgoing.setRemoteDescription({
		type: 'offer',
		sdp: sdp(fingerprint, 'gather', 'active', candidates)
	});
	const answer = await outgoing.createAnswer();
	answer.sdp = answer.sdp
		.replace(/a=ice-ufrag:.+/img, 'a=ice-ufrag:' + address)
		.replace(/a=ice-pwd:.+/img, 'a=ice-pwd:' + ice_pwd);
	await outgoing.setLocalDescription(answer);

	document.body.append(new ConnViewer(outgoing));
} catch (e) { console.warn('Failed to connect to address:', e); }


// Use peer reflixive candidates on the gatherer to detect incoming connections:
const incomings = new Map();
setInterval(async () => {
	const stats = await gatherer.getStats();
	const values = Array.from(stats.values());

	for (const {usernameFragment, port} of values.filter(v => v.type == 'remote-candidate')) {
		try {
			const buffer = new Uint8Array(
				Array.from(atob(usernameFragment), s => s.charCodeAt(0))
			);
			const fingerprint = buffer.subarray(0, 32).reduce(
				(a, v, i) => a + (i ? ':' : '') + v.toString(16).padStart(2, '0'),
				''
			);
			const candidates = [];
			const view = new DataView(buffer.buffer, 30);
			for (let i = 0; i + 2 < view.byteLength;) {
				const ip = Array.from({length: 8}, () => view.getUint16(i += 2).toString(16)).join(':');
				const _gatherer_port = view.getUint16(i += 2); // We don't want the port of their gatherer, we will instead use the discovered port from the remote candidate.
				candidates.push(`a=candidate:foundation 1 udp 42 ${ip} ${port} typ relay raddr :: rport 0`);
			}

			let incoming = incomings.get(fingerprint);
			if (!incoming) {
				incoming = new RTCPeerConnection(config);
				document.body.append(new ConnViewer(incoming));
				incomings.set(fingerprint, incoming);

				await incoming.setRemoteDescription({
					type: 'offer',
					sdp: sdp(fingerprint, usernameFragment, 'passive', candidates)
				});
				const answer = await incoming.createAnswer();
				answer.sdp = answer.sdp
					.replace(/a=ice-ufrag:.+/img, 'a=ice-ufrag:' + ice_ufrag)
					.replace(/a=ice-pwd:.+/img, 'a=ice-pwd:' + ice_pwd);
				await incoming.setLocalDescription(answer);
			} else {
				// TODO: Add prflx candidates to existing connections?
			}
		} catch (e) { console.warn('handling remote candidate', e); }
	}
}, 100);
