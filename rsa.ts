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
const getRandomNBitNumber = (nBit: number): number =>
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
const getNBitPrime = (nBit: number): number => {
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

interface KeyPair {
  priv: {
    d: number;
    N: number;
  };
  publ: {
    e: number;
    N: number;
  };
}

/**
 * (Horrible) RSA key generation.
 * @see https://en.wikipedia.org/wiki/RSA_(cryptosystem)
 * @returns
 */
const generateKeysIterative = (nBit: number, e_override?: number): KeyPair => {
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
  const priv = { d, N };
  const publ = { e, N };
  console.timeEnd("Generate");
  return {
    priv,
    publ,
  };
};

/**
 * Convert a string to an array of char codes.
 * @param string A String to be converted.
 * @returns An array of char code numbers.
 */
const stringToCharCodeArray = (string: string): number[] =>
  string.split("").map((val) => val.charCodeAt(0));

/**
 * Convert an array of char codes to a string.
 * @param array An array of char code numbers
 * @returns A string defined by the char code array.
 */
const charCodeArrayToString = (array: number[]): string =>
  array.map((val) => String.fromCharCode(val)).join("");

/**
 * Encrypt a single number.
 * @param x The number to be encrypted.
 * @param publ The public key.
 * @returns The encrypted number.
 */
const encryptNumber = (x: number, publ: KeyPair["publ"]): number =>
  parseInt((BigInt(x) ** BigInt(publ.e) % BigInt(publ.N)).toString());

/**
 * Decrypt a single number.
 * @param x The number to be decrypted.
 * @param priv The private key.
 * @returns The decrypted number.
 */
const decryptNumber = (x: number, priv: KeyPair["priv"]): number =>
  parseInt((BigInt(x) ** BigInt(priv.d) % BigInt(priv.N)).toString());

/**
 * Encrypt a string message.
 * @param message The message to be encrypted.
 * @param publ The public key.
 * @returns The encrypted message as an array of numbers in which each number represents the encrypted char code.
 * @see encryptNumber
 */
const encrypt = (message: string, publ: KeyPair["publ"]): number[] => {
  console.time("Encrypt");
  const result = stringToCharCodeArray(message).map((item) =>
    encryptNumber(item, publ)
  );
  console.timeEnd("Encrypt");
  return result;
};

/**
 * Decrypt a string message.
 * @param cipher The cipher to be decrypted as an array of numbers in which each number represents the encrypted char code.
 * @param priv The private key.
 * @returns The decrypted string.
 * @see decryptNumber
 */
const decrypt = (cipher: number[], priv: KeyPair["priv"]): string => {
  console.time("Decrypt");
  const charCodeArray = cipher.map((item) => decryptNumber(item, priv));
  const result = charCodeArrayToString(charCodeArray);
  console.timeEnd("Decrypt");
  return result;
};

/**
 * Helper function for logging a result to console.
 * @param m The clear text message.
 * @param cipher The cipher text.
 * @param decrypted The decrypted text.
 * @param keyPair The key pair.
 * @param keyLength The key length in bit.
 */
const logResults = (
  m: string,
  cipher: number[],
  decrypted: string,
  keyPair?: KeyPair,
  keyLength?: number
) => {
  const obj: any = {};
  obj["message"] = m;
  obj["encrypted"] = charCodeArrayToString(cipher);
  obj["decrypted"] = decrypted;
  obj["equal"] = m === decrypted;
  if (keyPair) {
    obj["private"] = keyPair.priv;
    obj["public"] = keyPair.publ;
  }
  if (keyLength) obj["length"] = keyLength + " Bit";
  console.log(obj);
};

const keyPair = generateKeysIterative(keyLength, eOverride);

const cipher = encrypt(message, keyPair.publ);

const decrypted = decrypt(cipher, keyPair.priv);

logResults(message, cipher, decrypted, keyPair, keyLength);
