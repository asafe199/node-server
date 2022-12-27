const crypto = globalThis.crypto;

exports.allyCreateToken = async (req, res, next) => {
    try {
        var data = await encryptData(req.body);
        var response = await post(data);
        var json = await response.json();
        res.send(json);
        res.status(response.status);
    } catch (e) {
        res.status(500).send({
            data: e
        });
    }
};

async function encryptData(body) {
    var dataBase64 = body.data;
    var uint8Array = base64StringToArrayBuffer(dataBase64);
    var jwks = {
        "alg": "RSA-OAEP-256",
        "e": "AQAB",
        "ext": true, 
        "key_ops": ["encrypt"],
        "kty": "RSA", 
        "n": "py5E88Thfnsfbmzo4cjdWJu7ITuD6xF7KCuIpS6uyP0_CUGznxwIr4EFcPPycxwBWNufxYRnVybxbXV6Ixa8J4xW-HVHR8ShYIaYjkUz1qyCsqW7txeYTDP52W5AxzgWmH9dpawQUawVX6nr7rZy7vM2YLbY126ozCj8NqRXTw8hHMkZh71ufuBDQzI6jnF05q3uKhdNPc9o2SEKS2qHhauUY4blE4D6X6spQBDSyeeGoOy43z9jJ7L4wEiP_MkXgL-if0EaF-QgejJ3PFo551VjU4SK6spRZ3wzQdNLHQlkRlFerYnXls8rn3T0Qz2M2UsxRdl51MYWxgU32KYPRQ"
    };
    var iv = crypto.getRandomValues(new Uint8Array(12));

    const key = await crypto.subtle.generateKey({
        name: 'AES-GCM',
        length: 256,
    }, true, ['encrypt', 'decrypt']);

    const ciphertext = await crypto.subtle.encrypt({ "iv": iv, "name": "AES-GCM" }, key, uint8Array);
    let encryptedData = arrayBufferToBase64(ciphertext);

    const importKey = await crypto.subtle.importKey('jwk', jwks, {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
    }, true, ['encrypt']);

    let publicKey = await crypto.subtle.exportKey('raw', key);
    let publicKeyBase64 = arrayBufferToBase64(publicKey);
    let ivBase64 = arrayBufferToBase64(iv);

    let textEncode = new TextEncoder().encode(JSON.stringify({ "symKey": publicKeyBase64, "iv": ivBase64 }));
    let response = await crypto.subtle.encrypt({
        "name": 'RSA-OAEP'
    }, importKey, textEncode);

    let encryptedKey = arrayBufferToBase64(response);

    return { "data": encryptedData, "key": encryptedKey, "dataType": "compressed" };
}

async function post(data) {
    return await fetch('https://secure.ally.com/acs/device/events', {
        method: 'POST',
        headers: {
            "Content-Type": 'application/json',
            "Accept": 'application/json',
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        },
        body: JSON.stringify(data)
    });
}

function arrayBufferToBase64(arrayBuffer) {
    return Buffer.from(arrayBuffer).toString('base64')
}

function base64StringToArrayBuffer(b64str) {
    return Buffer.from(b64str, 'base64');
}
