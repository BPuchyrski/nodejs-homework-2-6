// const fs = require('fs/promises')
const fs = require("fs").promises;
const path = require("path");
const { v4: uuidv4 } = require("uuid");

const contactsPath = path.join(__dirname, "./contacts.json");

const parsedData = async () => {
  try {
    const data = await fs.readFile(contactsPath, "utf-8");
    const contacts = JSON.parse(data);
    return contacts;
  } catch (error) {
    console.log(error);
  }
};

const listContacts = async () => {
  const contacts = await parsedData();
  return contacts;
};

const getContactById = async (contactId) => {
  const contacts = await fs.readFile(contactsPath, "utf-8");
  const contact = JSON.parse(contacts).find(
    (contact) => contact.id === contactId
  );
  return contact;
};

const removeContact = async (contactId) => {
  const contacts = await parsedData();
  const newContacts = contacts.filter((contact) => contact.id !== contactId);
  await fs.writeFile(contactsPath, JSON.stringify(newContacts));
  return newContacts;
};

const addContact = async (body) => {
  const contacts = await parsedData();
  const newContact = { id: uuidv4(), ...body };
  contacts.push(newContact);
  await fs.writeFile(contactsPath, JSON.stringify(contacts));
  return newContact;
};

const updateContact = async (contactId, body) => {
  const contacts = await parsedData();
  const indexPerson = contacts.findIndex((contact) => contact.id === contactId);
  if (indexPerson === -1) {
    return null;
  }
  const updatePerson = { ...contacts[indexPerson], ...body };
  contacts[indexPerson] = updatePerson;
  await fs.writeFile(contactsPath, JSON.stringify(contacts));
  return updatePerson;
};

module.exports = {
  listContacts,
  getContactById,
  removeContact,
  addContact,
  updateContact,
};
