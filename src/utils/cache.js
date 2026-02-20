const cache = new Map();

function set(key, value, ttlMs = 60000) {
  cache.set(key, {
    value,
    expires: Date.now() + ttlMs
  });
}

function get(key) {
  const data = cache.get(key);
  if (!data) return null;

  if (Date.now() > data.expires) {
    cache.delete(key);
    return null;
  }

  return data.value;
}

function del(key) {
  cache.delete(key);
}

module.exports = { set, get, del };