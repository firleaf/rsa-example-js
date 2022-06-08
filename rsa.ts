import { argv } from "process";

// ARGUMENTS
// Provide e.
const argE = argv.find((arg) => arg.startsWith("--e="))?.split("=")[1];
const eOverride = argE ? parseInt(argE) : undefined;

// Set key length in bit. Default is 16.
const argLength = argv
  .find((arg) => arg.startsWith("--length="))
  ?.split("=")[1];
const keyLength = parseInt(argLength ?? "16");

// Validate key length
if (keyLength % 2 !== 0)
  throw new Error("Key length has to be divisible by 2.");

// Set message to be encrypted.
const argMessage = argv
  .find((arg) => arg.startsWith("--message="))
  ?.split("=")[1];
const message = argMessage ?? "Hello World!";

/**
 * Super low effort primality test.
 * @param x Number to be tested.
 * @returns A Boolean whether the number supplied is a prime number or not.
 */
const isPrime = (x: number) => {
  for (let i = 2; i <= Math.sqrt(x); i++) {
    if (x % i === 0) return false;
  }
  return true;
};

/**
 * Get a random nBit long number.
 * @param nBit Length of number in bit.
 * @returns A nBit long number.
 */
const getRandomNBitNumber = (nBit: number) =>
  parseInt(
    new Array(nBit)
      .fill(null)
      .map((_, ind) => (ind === 0 ? 1 : Math.round(Math.random())))
      .join(""),
    2
  );

/**
 * Get a random nBit prime number.
 * @param nBit Length of number in bit.
 * @returns A nBit log prime number
 */
const getNBitPrime = (nBit: number) => {
  while (true) {
    const candidate = getRandomNBitNumber(nBit);
    if (isPrime(candidate)) return candidate;
  }
};

// EXTENDED EUCLID
/**
 * The iterative extended euclidian algorithm.
 * @see https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
 * @param x
 * @param y
 * @returns An object with `a`, `s` and `t` so that `s*x + t*y = a = gcd(x,y)`.
 */
const extendedEuclid = (
  x: number,
  y: number
): { a: number; s: number; t: number } => {
  let a = x;
  let b = y;
  let s = 1;
  let t = 0;
  let u = 0;
  let v = 1;
  while (b !== 0) {
    const q = Math.floor(a / b);
    const b1 = b;
    b = a - q * b;
    a = b1;
    const u1 = u;
    u = s - q * u;
    s = u1;
    const v1 = v;
    v = t - q * v;
    t = v1;
  }
  return { a, s, t };
};

//RSA KEYGEN
/**
 * (Horrible) RSA key generation.
 * @see https://en.wikipedia.org/wiki/RSA_(cryptosystem)
 * @returns
 */
const generateKeysIterative = (nBit: number, e_override?: number) => {
  console.time("Generate");
  let p: number;
  let q: number;
  let N: number;
  let e: number;
  let d: number;
  let phiN: number;
  let isFound = false;
  do {
    // Primes
    p = getNBitPrime(nBit / 2);
    q = getNBitPrime(nBit / 2);

    // Modulus (is nBit long)
    N = p * q;

    // Euler's totient function (instead of Carmichael function)
    phiN = (p - 1) * (q - 1);

    // Encryption exponent
    e = e_override ?? Math.floor(Math.random() * phiN);

    const { a, s } = extendedEuclid(e, phiN);

    // Decryption exponent
    d = s;

    // e and phiN are coprime
    const isE = a === 1 && e < phiN;

    // d is positive for use as exponent
    const isD = d >= 1;

    // p and q may not be equal
    const isEqual = p === q;

    isFound = !isEqual && isD && isE;
  } while (!isFound);
  const privateKey = { d, N };
  const publicKey = { e, N };
  console.timeEnd("Generate");
  return {
    privateKey,
    publicKey,
  };
};

const stringToCharCodeArray = (string: string) =>
  string.split("").map((val) => val.charCodeAt(0));

const charCodeArrayToString = (binArray: string[]) =>
  binArray.map((val) => String.fromCharCode(parseInt(val))).join("");

const encrypt = (text: string, publicKey: { e: number; N: number }) => {
  console.time("Encrypt");
  const result = stringToCharCodeArray(text).map((item) => {
    const value = BigInt(item);
    const exponent = BigInt(publicKey.e);
    const modulus = BigInt(publicKey.N);
    const result = value ** exponent % modulus;
    return result.toString();
  });
  console.timeEnd("Encrypt");
  return result;
};

const decrypt = (
  cipherText: string[],
  privateKey: { d: number; N: number }
) => {
  console.time("Decrypt");
  const charCodeArray = cipherText.map((item) => {
    const value = BigInt(item);
    const exponent = BigInt(privateKey.d);
    const modulus = BigInt(privateKey.N);
    const result = value ** exponent % modulus;
    return result.toString();
  });
  const result = charCodeArrayToString(charCodeArray);
  console.timeEnd("Decrypt");
  return result;
};

const keyPair = generateKeysIterative(keyLength, eOverride);

const cipherText = encrypt(message, keyPair.publicKey);

const decryptedText = decrypt(cipherText, keyPair.privateKey);

console.log({
  message: message,
  encrypted: charCodeArrayToString(cipherText),
  decrypted: decryptedText,
  equal: message === decryptedText,
  keyLength: keyLength + " Bit",
  ...keyPair,
});
