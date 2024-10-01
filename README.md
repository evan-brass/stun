# Masquerade
A stateless UDP server implementing a subset of the STUN / TURN protocol.  I wrote this because I want to run a free TURN server.

I'm running an instance of this server at stun.evan-brass.net.  Feel free to use it, as long as you read the caveats bellow.
```javascript
const config = {
	iceTransportPolicy: 'relay', // Force relaying because I want to show the TURN server in action.
	iceServers: [{urls: 'turn:stun.evan-brass.net', username: 'guest', credential: 'password'}],
};

const a = new RTCPeerConnection(config);
const b = new RTCPeerConnection(config);
a.createDataChannel('');

// Log connection states
a.addEventListener('connectionstatechange', () => console.log('a', a.connectionState));
b.addEventListener('connectionstatechange', () => console.log('b', b.connectionState));

// Negotiate the connection
await a.setLocalDescription();
while (a.iceGatheringState != 'complete') await new Promise(res => a.addEventListener('icegatheringstatechange', res, {once: true}));
await b.setRemoteDescription(a.localDescription);
await b.setLocalDescription();
while (b.iceGatheringState != 'complete') await new Promise(res => b.addEventListener('icegatheringstatechange', res, {once: true}));
await a.setRemoteDescription(b.localDescription);
```

# Caveats
1. Both sides of the connection need to include the same server in their list of iceServers.  This is because the relay candidates that this server generates / gives out can only successfully be paired with other relay candidates from the same server.  That's a side effect of the stateless workarounds this server uses.
2. UDP only.  This won't help you bypass corporate firewalls.
3. If browser behavior changes, it might break this server.
4. stun.evan-brass.net has a send cap so the server might not be available.  I also suck at devops so it might have died.

# Usage
My main goal is for this server to serve as a reverse proxy for ICE-Lite service that run without a public IP.  LipP2P's WebRTC transports don't currently support this, but maybe they will someday.  I'm also working on my own transport layer for WebRTC called [switchboard](https://github.com/evan-brass/swbrd) that I want to use this with.
