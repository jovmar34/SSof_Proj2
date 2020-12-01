a = document // a is (possibly) tainted by source document
b = a.url // b is (possibly) tainted by a.url
document.innerHTML = b //SINK