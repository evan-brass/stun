const mapped_prefix = [0, 0, 0, 0, 0, 0xffff];

export class Ip4 extends Uint8Array {
	constructor(...vals) { super(4); this.set(vals); }
	[Symbol.toPrimitive]() { return this.join('.'); }
	mapped() { return new Ip6(
		...mapped_prefix,
		this[0] << 8 | this[1],
		this[2] << 8 | this[3],
	); }
	canonical() { return this; }
}

export class Ip6 extends Uint16Array {
	constructor(...vals) { super(8); this.set(vals); }
	[Symbol.toPrimitive]() { return Array.from(this, n => n.toString(16)).join(':'); }
	mapped() { return this; }
	canonical() {
		if (mapped_prefix.every((v, i) => this[i] == v)) {
			return new Ip4(this[6] >> 8, this[6] & 0xFF, this[7] >> 8, this[7] & 0xFF);
		}
		return this;
	}
}

// Deno.NetAddr.hostname is a string that we need to parse into ipv4/ipv6 bytes (In order to encode it into STUN attributes)
// The Rust equivalent of what we need: (Not that I'm actually going to do as good a job as this)
// https://github.com/rust-lang/rust/blob/26089ba0a2d9dab8381ccb0d7b99e704bc5cb3ed/library/core/src/net/parser.rs#L224
function parse_ipv4(s) {
	const parts = s.split('.').map(s => parseInt(s, 10));
	if (parts.length == 4 && parts.every(b => b >= 0 && b < 2 ** 8)) {
		return new Ip4(...parts);
	}
}
export function parse_ipaddr(s) {
	const ret = new Ip6(0, 0, 0, 0, 0, 0xffff, 0, 0);
	let needed = 8;

	const parts = s.split(':');
	if (s.startsWith('::')) parts.splice(0, 1); // Collapse dual empty strings
	// Check if the last part is an ipv4:

	const v4 = parse_ipv4(parts[parts.length - 1]);
	if (v4) {
		parts.pop();
		ret[6] = v4[0] << 8 | v4[1];
		ret[7] = v4[2] << 8 | v4[3];
		needed -= 2;

		if (!parts.length) return v4;
	}

	// Handle `::`
	const ind = parts.indexOf('');
	if (ind < 0 && parts.length < needed) return;
	if (ind >= 0) parts[ind] = 0;
	while (parts.length < needed) parts.splice(ind, 0, 0);

	const nums = parts.map(s => parseInt(s, 16));
	if (nums.some(n => n < 0 || n >= 2 ** 16)) return;

	ret.set(nums);

	return ret;
}
