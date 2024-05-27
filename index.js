const crypto = require('crypto');

function adjust(a, a_off, b){
    x = (b[b.length-1] & 0xff) + (a[a_off + b.length-1] & 0xff) + 1

    a[a_off + b.length - 1] = x & 0xff

    x = x >> 8

    for(let i=b.length-2; i>-1; i--)
    {
        x = x + (b[i] & 0xff) + (a[a_off + i] & 0xff)
        a[a_off + i] = x & 0xff
        x = x >> 8
    }

}

function generate_derived_key(password, salt, iterations, id_byte, key_size){
    var u = 32
    var v = 64

    var d_key = new Array(key_size);

    for(let i=0; i<key_size.length;i++)
        d_key[i]=0x00

    var D =  new Array(64).fill(id_byte);

    S = []
    if((salt && salt.length)!=0){
        var s_size = v * parseInt((salt.length + v - 1) / v)
        S = new Array(s_size).fill(0x00)

        salt_size = salt.length
            for(let i=0; i<s_size; i++)
                S[i] = salt[i % salt_size]
    }

    P = []
    if ((password && password.length) != 0)
        var p_size = v * parseInt((password.length + v - 1) / v)
        P = new Array(p_size).fill(0x00)

        password_size = password.length
        for(let i=0; i<p_size; i++)
            P[i] = password[i % password_size]

    var I = S.concat(P)
    var I = Uint8Array.from(I)
    var B = new Array(key_size);
    for(let i=0; i<v.length;i++)
        B[i]=0x00
    var B = Uint8Array.from(B)

    var c = parseInt((key_size + u - 1) / u)

    for(let i=1; i<c+1;i++){
            var temp = Uint8Array.from(D)
            var value = crypto.createHash('sha256')            
            .update(temp)
            .update(I)
            .digest();

            var A = Uint8Array.from(value)
            // A = array('B', digest.digest())  # bouncycastle now resets the digest, we will create a new digest

            var hashIteration = 1;
            while (hashIteration++ < iterations) {
                var temp1 = crypto.createHash('sha256').update(A).digest();
                var A = Uint8Array.from(temp1)
           }

            for(let k =0; k<v; k++)
                B[k]=A[k%u]

            for(let j=0; j<parseInt(I.length/v); j++)  
                adjust(I, j*v, B)

            if(i==c){
                for(let j=0; j<key_size - ((i-1)*u); j++ )
                d_key[(i-1) * u + j] = A[j]
            }
            else{
                for(j=0; j<u; j++)
                    d_key[(i-1)*u+j] = A[j]
            }
    }
    return Uint8Array.from(d_key)
}

function generate_derived_parameters(password, salt, iterations, key_size, iv_size){

    const KEY_MATERIAL = 1
    const IV_MATERIAL = 2

    key_size = parseInt(key_size / 8)
    iv_size = parseInt(iv_size / 8)

    pkcs12_pwd = new Array((password.length + 1) * 2);
    for(let i=0; i<pkcs12_pwd.length;i++)
    pkcs12_pwd[i]=0x00;

        for(let i=0; i<password.length; i++){
            digit = password.charCodeAt(i);
            pkcs12_pwd[i * 2] = parseInt(digit >> 8)
            pkcs12_pwd[i * 2 + 1] = parseInt(digit)
        }
    var password_bytes = Uint8Array.from(pkcs12_pwd)

    d_key = generate_derived_key(password_bytes, salt, iterations,KEY_MATERIAL, key_size)
    if(iv_size && iv_size > 0)
    d_iv = generate_derived_key(password_bytes, salt, iterations, IV_MATERIAL, iv_size)
    else
    d_iv = null    
    
    return [d_key, d_iv]
}

/**
 * Decrypts the String Using a Password/Key
 * @param {string} string - The Encrypted String (BASE64 Encoded)
 * @param {string} password - The Password or Key for decryption
 * @returns {string}  The Decrypted String
 */
function decrypt(string, password){
    
    const p12b64=password;
    
    if(!p12b64){
        console.log('Please Check the password')
        return;
    }

    key_size_bits = 256
    iv_size_bits = 128
    
    // # decode the base64 encoded and encrypted secret
    const n_cipher_bytes = Buffer.from(string, 'base64');
    
    // # extract salt bytes 0 - SALT_SIZE
    var salt = n_cipher_bytes.slice(0,16);
    
    const [key, iv] = generate_derived_parameters(p12b64,salt,1000,key_size_bits,iv_size_bits)
    
    const cipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    n_cipher_message = n_cipher_bytes.subarray(16,)
    n_cipher_message = Uint8Array.from(n_cipher_message)
    let decrypted = cipher.update(n_cipher_message, 'base64','utf-8');
    decrypted += cipher.final();
    return decrypted;
}

module.exports = decrypt;