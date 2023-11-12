// ARGUMENTS
// Provide e.
const argE = Bun.argv.find((arg) => arg.startsWith("--e="))?.split("=")[1];
const eOverride = argE ? BigInt(argE) : undefined;

// Set key length in bit. Default is 16.
const argLength = Bun.argv
  .find((arg) => arg.startsWith("--length="))
  ?.split("=")[1];
const keyLength = parseInt(argLength ?? "16");

// Validate key length
if (keyLength % 2 !== 0)
  throw new Error("Key length has to be divisible by 2.");

// Set message to be encrypted.
const argMessage = Bun.argv
  .find((arg) => arg.startsWith("--message="))
  ?.split("=")[1];
const message = argMessage ?? "Hello World!";

/**
 * Calculate n-th root of val
 * Parameters:
 * k: is n-th (default sqare root)
 * limit: is maximum number of iterations (default: -1 no limit)
 * Thanks to Kamil Kiełczewski on Stackoverflow.
 * @see https://stackoverflow.com/questions/53683995/javascript-big-integer-square-root
 */
function nth_root(val: bigint, k = 2n, limit = -1) {
  let o = 0n; // old approx value
  let x = val;

  while (x ** k !== k && x !== o && --limit) {
    o = x;
    x = ((k - 1n) * x + val / x ** (k - 1n)) / k;
    if (limit < 0 && (x - o) ** 2n == 1n) break;
  }

  if ((val - (x - 1n) ** k) ** 2n < (val - x ** k) ** 2n) x = x - 1n;
  if ((val - (x + 1n) ** k) ** 2n < (val - x ** k) ** 2n) x = x + 1n;
  return x;
}

/**
 * Super low effort primality test.
 * @param x Number to be tested.
 * @returns A Boolean whether the number supplied is a prime number or not.
 */
const isPrime = (x: bigint) => {
  for (let i = 2n; i <= nth_root(x, 2n); i++) {
    if (x % i === 0n) return false;
  }
  return true;
};

/**
 * Get a random nBit long number.
 * @param nBit Length of number in bit.
 * @returns A nBit long number.
 */
const getRandomNBitNumber = (nBit: number): bigint =>
  BigInt(
    parseInt(
      new Array(nBit)
        .fill(null)
        .map((_, ind) => (ind === 0 ? 1 : Math.round(Math.random())))
        .join(""),
      2
    )
  );

/**
 * Get a random nBit prime number.
 * @param nBit Length of number in bit.
 * @returns A nBit log prime number
 */
const getNBitPrime = (nBit: number): bigint => {
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
  x: bigint,
  y: bigint
): { a: bigint; s: bigint; t: bigint } => {
  let a = x;
  let b = y;
  let s = 1n;
  let t = 0n;
  let u = 0n;
  let v = 1n;
  while (b !== 0n) {
    const q = a / b;
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
    d: bigint;
    N: bigint;
  };
  publ: {
    e: bigint;
    N: bigint;
  };
}

/**
 * (Horrible) RSA key generation.
 * @see https://en.wikipedia.org/wiki/RSA_(cryptosystem)
 * @returns
 */
const generateKeysIterative = (nBit: number, e_override?: bigint): KeyPair => {
  console.time("Generate");
  let p: bigint;
  let q: bigint;
  let N: bigint;
  let e: bigint;
  let d: bigint;
  let phiN: bigint;
  let isFound = false;
  do {
    // Primes
    p = getNBitPrime(nBit / 2);
    q = getNBitPrime(nBit / 2);

    // Modulus (is nBit long)
    N = p * q;

    // Euler's totient function (instead of Carmichael function)
    phiN = (p - 1n) * (q - 1n);

    // Encryption exponent
    e = e_override ?? BigInt(Math.floor(Math.random() * Number(phiN)));

    const { a, s } = extendedEuclid(e, phiN);

    // Decryption exponent
    d = s;

    // e and phiN are coprime
    const isE = a === 1n && e < phiN;

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
const encryptNumber = (x: bigint, publ: KeyPair["publ"]): bigint =>
  x ** publ.e % publ.N;

/**
 * Decrypt a single number.
 * @param x The number to be decrypted.
 * @param priv The private key.
 * @returns The decrypted number.
 */
const decryptNumber = (x: bigint, priv: KeyPair["priv"]): bigint =>
  x ** priv.d % priv.N;

/**
 * Encrypt a string message.
 * @param message The message to be encrypted.
 * @param publ The public key.
 * @returns The encrypted message as an array of numbers in which each number represents the encrypted char code.
 * @see encryptNumber
 */
const encrypt = (message: string, publ: KeyPair["publ"]): bigint[] => {
  console.time("Encrypt");
  const result = stringToCharCodeArray(message).map((item) =>
    encryptNumber(BigInt(item), publ)
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
const decrypt = (cipher: bigint[], priv: KeyPair["priv"]): string => {
  console.time("Decrypt");
  const charCodeArray = cipher.map((item) => Number(decryptNumber(item, priv)));
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
  cipher: bigint[],
  decrypted: string,
  keyPair?: KeyPair,
  keyLength?: number
) => {
  const obj: any = {};
  obj["message"] = m;
  obj["encrypted"] = charCodeArrayToString(cipher.map((item) => Number(item)));
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
