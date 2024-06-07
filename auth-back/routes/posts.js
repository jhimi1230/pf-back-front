const express = require("express");
const router = express.Router();
const Todo = require("../schema/todo");
const crypto = require('crypto');
const argon2 = require('argon2');
const { generateKeyPairSync, createSign, createVerify } = require('crypto');

// Generar par de llaves RSA
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Función para firmar datos
function signData(data, privateKey) {
  const sign = createSign('SHA256');
  sign.update(data);
  sign.end();
  return sign.sign(privateKey, 'hex');
}

// Función para verificar la firma
function verifySignature(data, signature, publicKey) {
  const verify = createVerify('SHA256');
  verify.update(data);
  verify.end();
  return verify.verify(publicKey, signature, 'hex');
}

// Función para generar HMAC
function generateHMAC(data, key) {
  const hmac = crypto.createHmac('sha256', key);
  hmac.update(data);
  return hmac.digest('hex');
}

// Función para verificar HMAC
function verifyHMAC(data, key, hmacToVerify) {
  const hmac = generateHMAC(data, key);
  return hmac === hmacToVerify;
}

// Función para cifrar datos utilizando AES
function encryptAES(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encryptedData = cipher.update(data, 'utf8', 'hex');
  encryptedData += cipher.final('hex');
  return iv.toString('hex') + ':' + encryptedData;
}

// Función para descifrar datos utilizando AES
function decryptAES(encryptedData, key) {
  const [ivHex, encryptedText] = encryptedData.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decryptedData = decipher.update(encryptedText, 'hex', 'utf8');
  decryptedData += decipher.final('utf8');
  return decryptedData;
}

// Función para generar una clave a partir de una contraseña
function getKeyFromPassword(password) {
  return crypto.createHash('sha256').update(password).digest();
}

function compararTipoHash(info) {
  let { id, data, tipohash, hash } = info;
  if (tipohash === 'Firma Digital') {
    hash = signData(data, privateKey);
    hash = hash + ';;;' + publicKey;
    return { data, tipohash, hash };
  } else if (tipohash === 'Almacenamiento Seguro de Contraseña') {
    hash = getKeyFromPassword(id);
    const encryptedData = encryptAES(data, hash);
    data = encryptedData;
    hash = hash.toString('hex');
    return { data, tipohash, hash };
  } else if (tipohash === 'Datos en Reposo') {
    hash = getKeyFromPassword(id);
    const encryptedData = encryptAES(data, hash);
    data = encryptedData;
    hash = hash.toString('hex');
    return { data, tipohash, hash };

  } else if (tipohash === 'Autenticidad de Datos') {
    const hmac = generateHMAC(data, id);
    hash = hmac;
    return { data, tipohash, hash };
  } else {
    return console.log('Tipo de hash no reconocido');
  }
}


router.get("/", async (req, res) => {
  try {
    const items = await Todo.find({ idUser: req.user.id });
    const mappedItems = items.map(item => {
      let { data, tipohash, id, hash } = item;
      if (tipohash === 'Firma Digital') {
        const verificar = hash.split(';;;');
        const isValidSignature = verifySignature(data, verificar[0], verificar[1]);
        if (isValidSignature) {
          hash = hash + "\n " + "la firma es válida";
        } else {
          hash = hash + "\n " + "la firma no es válida";
        }
        return { data, tipohash, id, hash };
      } else if (tipohash === 'Almacenamiento Seguro de Contraseña') {
        const retrievedHashBuffer = Buffer.from(hash, 'hex');
        data = decryptAES(data, retrievedHashBuffer);
        return { data, tipohash, id, hash };
      } else if (tipohash === 'Datos en Reposo') {
        const retrievedHashBuffer = Buffer.from(hash, 'hex');
        data = decryptAES(data, retrievedHashBuffer);
        return { data, tipohash, id, hash };
      } else if (tipohash === 'Autenticidad de Datos') {
        const isValidHMAC = verifyHMAC(data, id, hash);
        if (isValidHMAC) {
        } else {
        }
        return { data, tipohash, id, hash };
      } else {
        console.log('Tipo de hash no reconocido');
        return null;
      }
    });
    res.json(mappedItems);

  } catch (error) {
    console.log(error);
    return res.status(500).json({ error: "Error al obtener los todos" });
  }
});

router.post("/", async (req, res) => {
  if (!req.body.data) {
    return res.status(400).json({ error: "Title is required" });
  }

  try {
    const { data, tipohash } = req.body;
    let hash = "ongoing";
    const id = req.user.id;
    let todo = new Todo({ id, data, tipohash, hash });
    const dataparaencritpar = compararTipoHash(todo);
    todo = new Todo({
      idUser: req.user.id,
      data: dataparaencritpar.data,
      tipohash: req.body.tipohash,
      hash: dataparaencritpar.hash,
    });
    const todoInfo = await todo.save();
    res.json(todoInfo);
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error al crear el todo" });
  }
});

module.exports = router;
