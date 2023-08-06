const sha256 = (message: string): string => {
    const BLOCK_SIZE = 64; // 512 bits
    const HASH_SIZE = 32; // 256 bits

    var H: number[] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    const K: number[] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    function rightRotate(x: number, n: number): number {
        return (x >>> n) | (x << (32 - n));
    }

    function utf8ToBytes(str: string): Uint8Array {
        const encoder = new TextEncoder();
        return encoder.encode(str);
    }

    function bytesToHex(bytes: number[]): string {
        return Array.from(bytes)
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('');
    }

    function padMessage(message: Uint8Array): Uint8Array {
        const len = message.length * 8; // Message length in bits
        const paddingLength = (BLOCK_SIZE - ((len + 1 + 64) % BLOCK_SIZE)) % BLOCK_SIZE;
        const padded = new Uint8Array(message.length + paddingLength + 8);

        padded.set(message);
        padded[message.length] = 0x80; // Add 1 bit after the message
        for (let i = 0; i < 8; i++) {
            padded[padded.length - 8 + i] = (len >>> (56 - i * 8)) & 0xff;
        }

        return padded;
    }

    function processBlock(block: Uint8Array, H: number[]): number[] {
        const W: number[] = new Array(64);
        const tempH: number[] = [...H];

        // Prepare the message schedule W
        for (let t = 0; t < 16; t++) {
            W[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) | (block[t * 4 + 2] << 8) | block[t * 4 + 3];
        }

        for (let t = 16; t < 64; t++) {
            const s0 = rightRotate(W[t - 15], 7) ^ rightRotate(W[t - 15], 18) ^ (W[t - 15] >>> 3);
            const s1 = rightRotate(W[t - 2], 17) ^ rightRotate(W[t - 2], 19) ^ (W[t - 2] >>> 10);
            W[t] = (W[t - 16] + s0 + W[t - 7] + s1) & 0xffffffff;
        }

        // Compression function
        let [a, b, c, d, e, f, g, h] = tempH;

        for (let t = 0; t < 64; t++) {
            const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);

            const ch = (e & f) ^ (~e & g);
            const maj = (a & b) ^ (a & c) ^ (b & c);

            const temp1 = (h + S1 + ch + K[t] + W[t]) & 0xffffffff;
            const temp2 = (S0 + maj) & 0xffffffff;


            h = g;
            g = f;
            f = e;
            e = (d + temp1) & 0xffffffff;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) & 0xffffffff;
        }

        // Update the hash values (H)
        H[0] = (H[0] + a) & 0xffffffff;
        H[1] = (H[1] + b) & 0xffffffff;
        H[2] = (H[2] + c) & 0xffffffff;
        H[3] = (H[3] + d) & 0xffffffff;
        H[4] = (H[4] + e) & 0xffffffff;
        H[5] = (H[5] + f) & 0xffffffff;
        H[6] = (H[6] + g) & 0xffffffff;
        H[7] = (H[7] + h) & 0xffffffff;

        return H;
    }


    const messageBytes = utf8ToBytes(message);
    const paddedMessage = padMessage(messageBytes);
    for (let i = 0; i < paddedMessage.length; i += BLOCK_SIZE) {
        const block = paddedMessage.subarray(i, i + BLOCK_SIZE);
        H = processBlock(block, H);
    }

    const hashBytes = new Uint8Array(HASH_SIZE);
    for (let i = 0; i < HASH_SIZE; i++) {
        hashBytes[i] = (H[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }

    // Return the computed hash as a hex string
    return bytesToHex(hashBytes as any);
}

// Example usage:
const message = 'Hello, world!';
const hash = sha256(message);
console.log(hash);
