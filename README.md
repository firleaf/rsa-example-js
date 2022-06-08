# rsa-example

Very dirty implementation example of the [RSA algorithm](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)>). Meant only for learning purposes.

## Usage

### Install and build

```bash
npm i
npm run build
```

### Run

```bash
node dist/rsa.js [--options]
```

```bash
npm run rsa -- [--options]
```

## Options

| Option                    | Default         | Description                                                           |
| ------------------------- | --------------- | --------------------------------------------------------------------- |
| `--message="Hello World"` | `"Hello World"` | Set a message to be encrypted.                                        |
| `--length=16`             | `16`            | Select the key length. Has to be divisible by 2.                      |
| `--e=`                    | `undefined`     | Set the public key exponent rather than letting the algorithm choose. |
