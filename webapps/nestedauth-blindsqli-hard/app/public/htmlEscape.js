(function (root) {
  var ESCAPE_MAP = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (char) {
      return ESCAPE_MAP[char];
    });
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { escapeHtml: escapeHtml };
  } else {
    root.escapeHtml = escapeHtml;
  }
})(typeof window !== 'undefined' ? window : this);
