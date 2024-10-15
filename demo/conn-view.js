export class ConnViewer extends HTMLElement {
	constructor(conn) {
		super();
		const chat = conn.createDataChannel('chat', {negotiated: true, id: 20});

		this.attachShadow({mode: 'open'});
		this.shadowRoot.innerHTML = `
			<form style="display: inline-block; border: 1px solid salmon;">
				<label>State: <output name="state">${conn.connectionState}</output></label>
				<button name="close">Close</button>
				<pre><output name="recv"></output></pre>
				<textarea name="msg"></textarea>
				<button name="send" disabled>Send</button>
			</form>
		`;
		const elements = this.shadowRoot.querySelector('form').elements;
		chat.addEventListener('open', () => elements["send"].removeAttribute('disabled'));
		chat.addEventListener('close', () => elements["send"].setAttribute('disabled', ''));
		this.shadowRoot.addEventListener('submit', e => {
			e.preventDefault();
			const { submitter } = e;
			if (submitter.name == 'close') conn.close();
			else if (submitter.name == 'send' && chat.readyState == 'open') {
				chat.send(elements["msg"].value);
			}
		});
		conn.addEventListener('connectionstatechange', () => {
			elements["state"].innerText = conn.connectionState;
		});
		chat.addEventListener('message', ({ data }) => {
			if (typeof data != 'string') return;
			elements["recv"].append(new Text(data + '\n'));
		});
	}
}

customElements.define('conn-viewer', ConnViewer);
