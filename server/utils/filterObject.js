const filterObject = (obj, ...allowedObject) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedObject.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

module.exports = filterObject;