//
// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.
//

'use strict';

const extend = require('extend');

const azureCommon = require('./../../../common/common');
const SR = azureCommon.SR;
const Constants = azureCommon.Constants;
const entityGenerator = require('../tableutilities').entityGenerator;

// ----------------------------------------------------------------------------
// This is a Node.js implementation of client-side table entity encryption,
// compatible with the official Azure storage .NET library.
// ----------------------------------------------------------------------------

const async = require('async');
const crypto = require('crypto');
const jose = require('node-jose');

// ----------------------------------------------------------------------------
// Azure Storage .NET client library - entity encryption keys:
//
// Key:      _ClientEncryptionMetadata1
// Type:     JSON stringified object
// Purpose:  Contains information about the client encryption agent used to
//           encrypt the entity. Contains a uniquely generated content
//           encryption key for the specific row of data.
// Constant: tableEncryptionKeyDetails
//
// Key:      _ClientEncryptionMetadata2
// Type:     Binary buffer
// Purpose:  Encrypted JSON stringified object containing the list of encrypted
//           fields in the entity.
// Constant: tableEncryptionPropertyDetails
// ----------------------------------------------------------------------------
const tableEncryptionPropertyDetails = '_ClientEncryptionMetadata2';
const tableEncryptionKeyDetails = '_ClientEncryptionMetadata1';

// ----------------------------------------------------------------------------
// Azure Storage encryption agent values: as implemented today, the encryption
// agent for .NET is of version 1.0; initialization vectors are 16-bytes,
// CEKs are 32-bytes, etc. The agent includes the AES algorithm used for
// content keys, but the algorithm is the .NET framework-recognized value and
// not the OpenSSL defined constant. We maintain a map therefore to map
// between the two, but only those which are currently supported by the .NET
// Azure Storage library.
// ----------------------------------------------------------------------------
const azureStorageEncryptionAgentProtocol = '1.0';
const azureStorageKeyWrappingAlgorithm = 'A256KW';
const azureStorageContentEncryptionIVBytes = 16;
const azureStorageContentEncryptionKeyBytes = 32;
const azureStorageEncryptionAgentEncryptionAlgorithm = 'AES_CBC_256' /* .NET value */;
const mapDotNetFrameworkToOpenSslAlgorithm = new Map([[azureStorageEncryptionAgentEncryptionAlgorithm, 'aes-256-cbc']]);

function openSslFromNetFrameworkAlgorithm(algorithm) {
  const openSslAlgorithm = mapDotNetFrameworkToOpenSslAlgorithm.get(algorithm);
  if (openSslAlgorithm === undefined) {
    throw new Error(`The OpenSSL algorithm constant for the .NET Framework value "${algorithm}" is not defined or tested.`);
  }
  return openSslAlgorithm;
}

// ----------------------------------------------------------------------------
// Hash, encrypt, decrypt, wrap, unwrap and key generation routines
// ----------------------------------------------------------------------------
function getSha256Hash(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

function encryptValue(contentEncryptionKey, iv, value) {
  const cipher = crypto.createCipheriv(openSslFromNetFrameworkAlgorithm(azureStorageEncryptionAgentEncryptionAlgorithm), contentEncryptionKey, iv);
  return Buffer.concat([cipher.update(value), cipher.final()]);
}

function decryptValue(algorithm, contentEncryptionKey, iv, encryptedValue) {
  const decipher = crypto.createDecipheriv(algorithm, contentEncryptionKey, iv);
  return Buffer.concat([decipher.update(encryptedValue), decipher.final()]);
}

function generate32bitKey(callback) {
  crypto.randomBytes(azureStorageContentEncryptionKeyBytes, callback);
}

function generateContentEncryptionKey(callback) {
  crypto.randomBytes(azureStorageContentEncryptionIVBytes, (cryptoError, contentEncryptionIV) => {
    if (cryptoError) {
      return callback(cryptoError);
    }
    generate32bitKey((createKeyError, contentEncryptionKey) => {
      if (createKeyError) {
        return callback(createKeyError);
      }
      callback(null, contentEncryptionIV, contentEncryptionKey);
    });
  });
}

function wrapContentKey(keyWrappingAlgorithm, keyEncryptionKey, contentEncryptionKey, callback) {
  jose.JWA.encrypt(keyWrappingAlgorithm, keyEncryptionKey, contentEncryptionKey)
    .then((result) => {
      return callback(null, result.data);
    }, callback);
}

function unwrapContentKey(keyWrappingAlgorithm, keyEncryptionKey, wrappedContentKeyEncryptedKey, callback) {
  jose.JWA.decrypt(keyWrappingAlgorithm, keyEncryptionKey, wrappedContentKeyEncryptedKey)
    .then((contentEncryptionKey) => {
      return callback(null, contentEncryptionKey);
    }, callback);
}

// ----------------------------------------------------------------------------
// Azure encryption metadata object
// ----------------------------------------------------------------------------
function createEncryptionData(keyId, wrappedContentEncryptionKey, contentEncryptionIV, keyWrappingAlgorithm) {
  const encryptionData = {
    /* PascalCase object per the .NET library */
    WrappedContentKey: {
      KeyId: keyId,
      EncryptedKey: base64StringFromBuffer(wrappedContentEncryptionKey),
      Algorithm: keyWrappingAlgorithm,
    },
    EncryptionAgent: {
      Protocol: azureStorageEncryptionAgentProtocol,
      EncryptionAlgorithm: azureStorageEncryptionAgentEncryptionAlgorithm,
    },
    ContentEncryptionIV: base64StringFromBuffer(contentEncryptionIV),
    KeyWrappingMetadata: {},
  };
  return encryptionData;
}

function validateEncryptionData(encryptionData) {
  if (!encryptionData || !encryptionData.EncryptionAgent) {
    throw new Error('No encryption data or encryption data agent.');
  }
  const agent = encryptionData.EncryptionAgent;
  if (!agent.Protocol) {
    throw new Error('Encryption agent protocol version must be present in the encryption data properties.');
  }
  if (agent.Protocol !== azureStorageEncryptionAgentProtocol) {
    throw new Error(`Encryption agent value "${agent.EncryptionAgent}" is not recognized or tested with this library.`);
  }
  if (!agent.EncryptionAlgorithm) {
    throw new Error('Encryption algorithm type must be present in the encryption data properties.');
  }
  if (!mapDotNetFrameworkToOpenSslAlgorithm.get(agent.EncryptionAlgorithm)) {
    throw new Error(`Encryption agent value "${agent.EncryptionAgent}" is not recognized or tested with this library.`);
  }
}

function resolveKeyEncryptionKeyFromOptions(encryptionOptions, keyId, callback) {
  if (!encryptionOptions) {
    return callback(new Error('Encryption options must be specified.'));
  }
  if (!keyId) {
    throw new Error('No key encryption key ID provided.');
  }
  if ((!encryptionOptions.keyEncryptionKeys || typeof encryptionOptions.keyEncryptionKeys !== 'object') && (!encryptionOptions.keyResolver || typeof encryptionOptions.keyResolver !== 'function')) {
    return callback(new Error('Encryption options must provide either a "keyResolver" function or "keyEncryptionKeys" object.'));
  }
  const resolver = encryptionOptions.keyResolver || function (keyId, callback) {
    const key = encryptionOptions.keyEncryptionKeys[keyId];
    callback(null, key);
  };
  resolver(keyId, (resolveError, key) => {
    if (resolveError) {
      return callback(resolveError);
    }
    if (!key) {
      return callback(new Error(`We were not able to retrieve a key with identifier "${keyId}".`));
    }
    return callback(null, bufferFromBase64String(key));
  });
}

// ----------------------------------------------------------------------------
// Compute Truncated Column Hash:
// Each encrypted entity (row) has its own content encryption key, init vector,
// and then each column is encrypted using an IV that comes from key table
// properties, the row identity and the column name.
// ----------------------------------------------------------------------------
function computeTruncatedColumnHash(contentEncryptionIV, partitionKey, rowKey, columnName) {
  // IMPORTANT:
  // The .NET storage library (the reference implementation for Azure client-side
  // storage) has a likely bug in the ordering and concatenation of parameters
  // to generate the truncated column hash; it uses string.Join(partitionKey, rowKey, column)
  // instead of String.Concat. The likely original intention of the author seems
  // to be a concat in the order of partition key, row key, and then column, but
  // instead the resulting string is actually row key, partition key, column,
  // because string.Join treats the first parameter (the partition key in this
  // case) as the separator for joining an array of values. This code uses array
  // join to identically reproduce the .NET behavior here so that the two
  // implementations remain compatible.
  const columnIdentity = new Buffer([rowKey, columnName].join(partitionKey), 'utf8');
  const combined = Buffer.concat([contentEncryptionIV, columnIdentity]);
  const hash = getSha256Hash(combined);
  return hash.slice(0, azureStorageContentEncryptionIVBytes);
}

// ----------------------------------------------------------------------------
// Buffer/string functions
// ----------------------------------------------------------------------------
function base64StringFromBuffer(val) {
  return Buffer.isBuffer(val) ? val.toString('base64') : val;
}

function bufferFromBase64String(val) {
  return Buffer.isBuffer(val) ? val : new Buffer(val, 'base64');
}

function translateBuffersToBase64(properties) {
  for (const key in properties) {
    if (Buffer.isBuffer(properties[key])) {
      properties[key] = base64StringFromBuffer(properties[key]);
    }
  }
  return properties;
}

// ----------------------------------------------------------------------------
// The default encryption resolver implementation: given a list of properties
// to encrypt, return true when that property is being processed.
// ----------------------------------------------------------------------------
function createDefaultEncryptionResolver(propertiesToEncrypt) {
  const encryptedKeySet = propertiesToEncrypt && propertiesToEncrypt.has ? propertiesToEncrypt : new Set(propertiesToEncrypt);
  // Default resolver does not use partition/row, but user could
  return (partition, row, name) => {
    return encryptedKeySet.has(name);
  };
}

function encryptProperty(contentEncryptionKey, contentEncryptionIV, partitionKey, rowKey, property, value) {
  let columnIV = computeTruncatedColumnHash(contentEncryptionIV, partitionKey, rowKey, property);
  // Store the encrypted properties as binary values on the service instead of
  // base 64 encoded strings because strings are stored as a sequence of WCHARs
  // thereby further reducing the allowed size by half. During retrieve, it is
  // handled by the response parsers correctly even when the service does not
  // return the type for JSON no-metadata.
  return encryptValue(contentEncryptionKey, columnIV, value);
}

function decryptProperty(aesAlgorithm, contentEncryptionKey, contentEncryptionIV, partitionKey, rowKey, propertyName, encryptedValue) {
  const columnIV = computeTruncatedColumnHash(contentEncryptionIV, partitionKey, rowKey, propertyName);
  return decryptValue(aesAlgorithm, contentEncryptionKey, columnIV, bufferFromBase64String(encryptedValue));
}

function encryptProperties(encryptionResolver, contentEncryptionKey, contentEncryptionIV, partitionKey, rowKey, entityDescriptor) {
  const encryptedProperties = {};
  const encryptedPropertiesList = [];
  const propertyNames = Object.getOwnPropertyNames(entityDescriptor);
  for (let i = 0; i < propertyNames.length; i++) {
    const property = propertyNames[i];
    if (property === Constants.TableConstants.ODATA_METADATA_MARKER) {
      continue;
    }
    if (property === tableEncryptionKeyDetails || property === tableEncryptionPropertyDetails) {
      throw new Error('A table encryption property is present in the entity properties to consider for encryption. The property must be removed.');
      // TODO: SR XXX
    }
    if (property === 'PartitionKey' || property === 'RowKey' || property === 'Timestamp' ) {
      continue;
    }
    if (encryptionResolver(partitionKey, rowKey, property) !== true) {
      continue;
    }

    if (entityDescriptor[property] === null || entityDescriptor[property] === undefined) {
      // TODO: SR; also, verify what the .NET client does here
      throw new Error(`Null or undefined properties cannot be encrypted. Property in question: ${property}`);
    }
    let value = typeof(entityDescriptor[property]) === 'object' && entityDescriptor[property].hasOwnProperty(Constants.TableConstants.ODATA_VALUE_MARKER) ? entityDescriptor[property][Constants.TableConstants.ODATA_VALUE_MARKER] : entityDescriptor[property];
    if (typeof value !== 'string') {
      // TODO: SR XXX
      throw new Error(`Property to be encrypted, ${property} with PartitionKey ${partitionKey} and RowKey ${rowKey}, is not of type 'string'`);
    }
    const encryptedValue = encryptProperty(contentEncryptionKey, contentEncryptionIV, partitionKey, rowKey, property, value);
    encryptedPropertiesList.push(property);
    entityDescriptor[property] = entityGenerator.Binary(encryptedValue);
  }
  return encryptedPropertiesList;
}

function decryptBody(body, encryptedPropertyNames, partitionKey, rowKey, contentEncryptionKey, encryptionData, contentEncryptionIV) {
  validateEncryptionData(encryptionData);
  const aesAlgorithm = openSslFromNetFrameworkAlgorithm(encryptionData.EncryptionAgent.EncryptionAlgorithm);
  for (let i = 0; i < encryptedPropertyNames.length; i++) {
    const propertyName = encryptedPropertyNames[i];
    const encryptedValue = body[propertyName];
    const value = decryptProperty(aesAlgorithm, contentEncryptionKey, contentEncryptionIV, partitionKey, rowKey, propertyName, encryptedValue);
    body[propertyName] = value.toString('utf8');
    body[propertyName + Constants.TableConstants.ODATA_TYPE_SUFFIX] = 'Edm.String';
  }
}

function encryptEntity(encryptionOptions, incomingDescriptor, callback) {
  // For performance reasons a user could opt-in to have their entityDescriptor object modified, by default it deep clones instead
  const entityDescriptor = encryptionOptions.modifyEntityDescriptor ? incomingDescriptor : extend(true, {}, incomingDescriptor);

  let partitionKey = null;
  let rowKey = null;

  if (typeof (entityDescriptor.PartitionKey) === 'string') {
    partitionKey = entityDescriptor.PartitionKey;
  } else {
    partitionKey = entityDescriptor.PartitionKey[Constants.TableConstants.ODATA_VALUE_MARKER];
  }

  if (typeof (entityDescriptor.RowKey) === 'string') {
    rowKey = entityDescriptor.RowKey;
  } else {
    rowKey = entityDescriptor.RowKey[Constants.TableConstants.ODATA_VALUE_MARKER];
  }

  if (typeof (rowKey) !== 'string' || typeof (partitionKey) !== 'string') {
    return callback(new Error(SR.INCORRECT_ENTITY_KEYS));
  }

  const encryptionPolicy = encryptionOptions.policy;
  if (!encryptionPolicy) {
    return callback(new Error('Must provide an encryption policy'));
    // TODO: SR XXX
  }

  const keyEncryptionKeyId = encryptionPolicy.keyEncryptionKeyId;
  if (!keyEncryptionKeyId) {
    // TODO: SR XXX
    return callback(new Error('Must provide a keyEncryptionKeyId'));
  }

  resolveKeyEncryptionKeyFromOptions(encryptionPolicy, keyEncryptionKeyId, (keyLocateError, keyEncryptionKey) => {
    if (keyLocateError) {
      return callback(keyLocateError);
    }
    let encryptionResolver = encryptionPolicy.encryptionResolver;
    if (!encryptionResolver) {
      const propertiesToEncrypt = encryptionPolicy.encryptedPropertyNames;
      if (!propertiesToEncrypt) {
        // TODO: XXX SR
        return callback(new Error('Encryption options must contain either a list of properties to encrypt or an encryption resolver.'));
      }
      encryptionResolver = createDefaultEncryptionResolver(propertiesToEncrypt);
    }
    generateContentEncryptionKey((generateKeyError, contentEncryptionIV, contentEncryptionKey) => {
      if (generateKeyError) {
        return callback(generateKeyError);
      }
      const keyWrappingAlgorithm = azureStorageKeyWrappingAlgorithm;
      wrapContentKey(keyWrappingAlgorithm, keyEncryptionKey, contentEncryptionKey, (wrapError, wrappedContentEncryptionKey) => {
        if (wrapError) {
          return callback(wrapError);
        }
        let encryptPropertiesList;
        try {
          encryptPropertiesList = encryptProperties(encryptionResolver, contentEncryptionKey, contentEncryptionIV, partitionKey, rowKey, entityDescriptor);
        } catch (encryptError) {
          return callback(encryptError);
        }
        if (encryptPropertiesList.length === 0) {
          return callback(null, entityDescriptor);
        }
        const metadataSerialized = JSON.stringify(encryptPropertiesList);
        entityDescriptor[tableEncryptionPropertyDetails] = entityGenerator.Binary(encryptProperty(contentEncryptionKey, contentEncryptionIV, partitionKey, rowKey, tableEncryptionPropertyDetails, metadataSerialized));
        entityDescriptor[tableEncryptionKeyDetails] = entityGenerator.String(JSON.stringify(createEncryptionData(keyEncryptionKeyId, jose.util.asBuffer(wrappedContentEncryptionKey), contentEncryptionIV, keyWrappingAlgorithm)));
        return callback(null, entityDescriptor);
      });
    });
  });
}

function decryptEntity(encryptionOptions, response, callback) {
  if (!response || !response.body || !response.body[tableEncryptionKeyDetails] || !response.body[tableEncryptionPropertyDetails]) {
    return callback(null, response && response.body ? response.body : null);
  }

  // xxx should this be modifyEntityResult or modifyEntityResponse?
  const body = encryptionOptions.modifyEntityDescriptor ? response.body : Object.assign({}, response.body);

  const partitionKey = body.PartitionKey;
  const rowKey = body.RowKey;

  let detailsValue = body[tableEncryptionKeyDetails];
  let tableEncryptionKey = null;
  try {
    tableEncryptionKey = JSON.parse(detailsValue);
  } catch (parseError) {
    return callback(parseError);
  }

  const iv = bufferFromBase64String(tableEncryptionKey.ContentEncryptionIV);
  const wrappedContentKey = tableEncryptionKey.WrappedContentKey;
  if (wrappedContentKey.Algorithm !== azureStorageKeyWrappingAlgorithm) {
    return callback(new Error(`The key wrapping algorithm "${wrappedContentKey.Algorithm}" is not tested or supported in this library.`));
  }
  const keyWrappingAlgorithm = wrappedContentKey.Algorithm;
  const wrappedContentKeyIdentifier = wrappedContentKey.KeyId;
  const wrappedContentKeyEncryptedKey = bufferFromBase64String(wrappedContentKey.EncryptedKey);

  const aesAlgorithm = openSslFromNetFrameworkAlgorithm(tableEncryptionKey.EncryptionAgent.EncryptionAlgorithm);

  const encryptionPolicy = encryptionOptions.policy || {};

  resolveKeyEncryptionKeyFromOptions(encryptionPolicy, wrappedContentKeyIdentifier, (kvkLocateError, kvk) => {
    if (kvkLocateError) {
      return callback(kvkLocateError);
    }
    const keyEncryptionKeyValue = bufferFromBase64String(kvk);
    unwrapContentKey(keyWrappingAlgorithm, keyEncryptionKeyValue, wrappedContentKeyEncryptedKey, (unwrapError, contentEncryptionKey) => {
      if (unwrapError) {
        return callback(unwrapError);
      }
      const metadataIV = computeTruncatedColumnHash(iv, partitionKey, rowKey, tableEncryptionPropertyDetails);
      const tableEncryptionDetails = bufferFromBase64String(body[tableEncryptionPropertyDetails]);
      try {
        const decryptedPropertiesSet = decryptValue(aesAlgorithm, contentEncryptionKey, metadataIV, tableEncryptionDetails);
        const listOfEncryptedProperties = JSON.parse(decryptedPropertiesSet.toString('utf8'));
        decryptBody(body, listOfEncryptedProperties, partitionKey, rowKey, contentEncryptionKey, tableEncryptionKey, iv);
        delete body[tableEncryptionKeyDetails];
        delete body[tableEncryptionPropertyDetails];
        delete body[tableEncryptionKeyDetails + Constants.TableConstants.ODATA_TYPE_SUFFIX];
        delete body[tableEncryptionPropertyDetails + Constants.TableConstants.ODATA_TYPE_SUFFIX];
        return callback(null, body);
      } catch (error) {
        return callback(error);
      }
    });
  });
}

module.exports = {
  decryptEntity: decryptEntity,
  encryptEntity: encryptEntity,
};
