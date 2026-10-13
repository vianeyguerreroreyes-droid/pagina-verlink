/* ============================================================
   VeriLink — prototipo de motor de análisis (demo web)
   Reglas heurísticas ejecutadas localmente en el navegador.
   ============================================================ */

(function () {
  "use strict";

  /* ---------- Datos de demostración ---------- */

  // Lista de prueba: dominios reportados en el conjunto de evaluación del PMV.
  var REPORTED_DOMAINS = {
    "banco-seguro-login": true,
    "banco-login-seguro": true,
    "dhl-parcel-fee": true,
    "secure-bbva-login": true,
    "paypal-verify-account": true,
    "netflix-billing-secure": true,
    "wa-confirm-account": true,
    "bbva-portal-clientes": true
  };

  var SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "rb.gy", "shorturl.at", "rebrand.ly"
  ];

  var SUSPICIOUS_TLDS = [
    "xyz", "top", "icu", "click", "live", "zip", "mov", "rest", "cfd",
    "loan", "win", "work", "men", "monster", "quest", "beauty", "hair",
    "tk", "ml", "ga", "cf", "gq", "buzz", "cam", "pics"
  ];

  // Marcas frecuentes imitadas por phishing, con su dominio real de referencia.
  var BRANDS = [
    { name: "paypal", real: "paypal.com" },
    { name: "bbva", real: "bbva.com" },
    { name: "santander", real: "santander.com" },
    { name: "bancolombia", real: "bancolombia.com" },
    { name: "mercadopago", real: "mercadopago.com" },
    { name: "dhl", real: "dhl.com" },
    { name: "fedex", real: "fedex.com" },
    { name: "netflix", real: "netflix.com" },
    { name: "whatsapp", real: "whatsapp.com" },
    { name: "instagram", real: "instagram.com" },
    { name: "facebook", real: "facebook.com" },
    { name: "google", real: "google.com" },
    { name: "microsoft", real: "microsoft.com" },
    { name: "amazon", real: "amazon.com" },
    { name: "apple", real: "apple.com" },
    { name: "banco", real: "" },
    { name: "bancoazteca", real: "bancoazteca.com" }
  ];

  // Etiquetas técnicas que no deben interpretarse como menciones a marcas.
  var GENERIC_LABELS = {
    "com": true, "net": true, "org": true, "www": true, "co": true,
    "gov": true, "edu": true, "web": true, "site": true, "online": true,
    "shop": true, "store": true, "app": true, "dev": true, "info": true
  };

  var RISK_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verificar", "verify",
    "verificacion", "verification", "secure", "security", "update",
    "account", "cuenta", "password", "confirm", "confirmar", "billing",
    "invoice", "pago", "pagar", "gift", "premio", "reward", "unlock",
    "blocked", "bloqueo", "reset", "wallet", "balance"
  ];

  /* ---------- Utilidades ---------- */

  function normalize(value) {
    return String(value || "").toLowerCase().trim();
  }

  function levenshtein(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;

    var prev = new Array(b.length + 1);
    var curr = new Array(b.length + 1);
    var i, j;

    for (j = 0; j <= b.length; j++) prev[j] = j;

    for (i = 1; i <= a.length; i++) {
      curr[0] = i;
      for (j = 1; j <= b.length; j++) {
        curr[j] = Math.min(
          prev[j] + 1,
          curr[j - 1] + 1,
          prev[j - 1] + (a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1)
        );
      }
      for (j = 0; j <= b.length; j++) prev[j] = curr[j];
    }
    return prev[b.length];
  }

  function signal(severity, title, detail) {
    return { severity: severity, title: title, detail: detail };
  }

  /* ---------- Análisis ---------- */

  function analyze(rawInput) {
    var raw = String(rawInput || "").trim();
    if (!raw) {
      return { error: "Escribe una dirección para analizar." };
    }

    // Se intenta interpretar la URL; si no trae protocolo se asume https.
    var candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : "https://" + raw;
    var url;

    try {
      url = new URL(candidate);
    } catch (err) {
      return { error: "No se pudo interpretar la dirección. Revisa que esté completa, por ejemplo https://ejemplo.com/pagina" };
    }

    if (!url.hostname || url.hostname.indexOf(".") === -1) {
      return { error: "La dirección no contiene un dominio válido." };
    }

    var signals = [];
    var hostname = url.hostname.toLowerCase();
    var labels = hostname.split(".");
    var registrable = labels.length >= 2 ? labels[labels.length - 2] : hostname;
    var tld = labels.length >= 1 ? labels[labels.length - 1] : "";
    var pathAndQuery = (url.pathname + url.search).toLowerCase();

    // 1. Protocolo sin cifrar
    if (url.protocol === "http:") {
      signals.push(signal("med",
        "La conexión no usa HTTPS",
        "La dirección comienza por http://, por lo que los datos que envíes viajan sin cifrar."));
    }

    // 2. Dirección IP en lugar de dominio
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.indexOf("[") === 0) {
      signals.push(signal("alto",
        "El destino es una dirección IP",
        "Los sitios legítimos suelen usar un dominio legible; una IP directa es habitual en páginas de prueba y en engaños."));
    }

    // 3. Codificación punycode (posibles caracteres falsos)
    var punycodeLabel = labels.some(function (label) { return label.indexOf("xn--") === 0; });
    if (punycodeLabel) {
      signals.push(signal("alto",
        "Dominio con caracteres internacionales codificados",
        "Etiquetas xn-- indican letras sustituidas por caracteres visuales parecidos: una técnica de imitación de marcas."));
    }

    // 4. Dominio reportado en la lista de prueba
    var reported = REPORTED_DOMAINS[registrable] ||
      REPORTED_DOMAINS[hostname] ||
      Object.keys(REPORTED_DOMAINS).some(function (entry) {
        return hostname.indexOf(entry) !== -1;
      });
    if (reported) {
      signals.push(signal("alto",
        "Dominio incluido en la lista de sitios reportados",
        "La dirección coincide con un enlace del conjunto de pruebas marcado como sospechoso."));
    }

    // 5. Imitación de marcas conocidas (cercanía ortográfica o token presente)
    var imitation = null;
    var brandMention = null;

    BRANDS.forEach(function (brand) {
      labels.forEach(function (label) {
        var cleanLabel = label.replace(/[^a-z0-9]/g, "");
        var cleanBrand = brand.name;

        if (!cleanLabel || !cleanBrand) return;
        if (GENERIC_LABELS[cleanLabel]) return;
        if (cleanLabel.length < 4 || cleanBrand.length < 4) return;

        if (cleanLabel !== cleanBrand &&
            (cleanLabel.indexOf(cleanBrand) !== -1 || cleanBrand.indexOf(cleanLabel) !== -1)) {
          brandMention = brand;
        }

        var distance = levenshtein(cleanLabel, cleanBrand);
        var tolerance = cleanBrand.length >= 6 ? 2 : 1;
        if (cleanLabel !== cleanBrand && distance <= tolerance) {
          imitation = brand;
        }
      });
    });

    if (imitation && imitation.name !== registrable) {
      signals.push(signal("alto",
        "El dominio imita la marca «" + imitation.name + "»",
        imitation.real
          ? "La diferencia con el dominio oficial (" + imitation.real + ") es mínima y puede pasar desapercibida."
          : "El término bancario se combina con elementos típicos de direcciones fabricadas."));
    } else if (brandMention && !isOfficialDomain(hostname, brandMention)) {
      signals.push(signal("med",
        "Usa el nombre de «" + brandMention.name + "» en un dominio distinto al oficial",
        brandMention.real
          ? "El dominio oficial de esa marca es " + brandMention.real + "; este no coincide."
          : "Las entidades bancarias oficiales usan su propio dominio; este no pertenece a ellos."));
    }

    // 6. Terminaciones poco habituales
    if (SUSPICIOUS_TLDS.indexOf(tld) !== -1) {
      signals.push(signal("med",
        "Terminación ." + tld + " poco habitual",
        "Esta terminación es frecuente en sitios de creación reciente y en campañas de engaño."));
    }

    // 7. Acortadores de URL
    var isShortener = SHORTENERS.some(function (domain) {
      return hostname === domain || hostname.slice(-(domain.length + 1)) === "." + domain;
    });
    if (isShortener) {
      signals.push(signal("med",
        "Enlace acortado",
        "No se puede ver el destino real hasta abrirlo; el acortador oculta el dominio de la página final."));
    }

    // 8. Estructura inusual del dominio
    var hyphens = (hostname.match(/-/g) || []).length;
    if (hyphens >= 3) {
      signals.push(signal("med",
        "Exceso de guiones en el dominio",
        "Los dominios legítimos rara vez usan tantos guiones; el patrón es común en variantes de phishing."));
    }

    var subdomains = labels.length - 2;
    if (subdomains >= 4) {
      signals.push(signal("med",
        "Demasiados subdominios (" + subdomains + ")",
        "Estructuras largas ocultan el dominio real y se usan para simular direcciones oficiales."));
    }

    if (hostname.length > 40) {
      signals.push(signal("med",
        "Dominio excesivamente largo",
        "Los dominios muy extensos dificultan reconocer cuál es la parte verdadera de la dirección."));
    }

    // 9. Credenciales incrustadas o símbolos raros
    if (raw.indexOf("@") !== -1 && url.username) {
      signals.push(signal("med",
        "La dirección oculta el destino real tras un «@»",
        "Todo lo anterior al símbolo @ es un usuario; el navegador visitará el dominio que viene después."));
    }

    if (/%[0-9a-f]{2}/i.test(url.hostname)) {
      signals.push(signal("alto",
        "El dominio contiene caracteres codificados",
        "Secuencias %XX en el host son inusuales y pueden esconder la verdadera letra del dominio."));
    }

    // 10. Palabras de riesgo en la ruta
    var keywordsFound = RISK_KEYWORDS.filter(function (word) {
      return pathAndQuery.indexOf(word) !== -1 || registrable.indexOf(word) !== -1;
    });
    if (keywordsFound.length >= 2) {
      signals.push(signal("med",
        "Vocabulario típico de verificación de cuentas",
        "La dirección contiene términos como «" + keywordsFound.slice(0, 3).join("», «") + "»."));
    }

    // 11. Nivel de riesgo
    var score = 0;
    var hasHigh = false;
    signals.forEach(function (item) {
      if (item.severity === "alto") { score += 4; hasHigh = true; }
      else if (item.severity === "med") { score += 2; }
      else { score += 1; }
    });

    var level;
    if (hasHigh || score >= 8) level = "alto";
    else if (score >= 2) level = "med";
    else level = "bajo";

    return {
      input: raw,
      url: url,
      level: level,
      score: score,
      signals: signals,
      parts: {
        protocolo: url.protocol.replace(":", ""),
        host: hostname,
        dominio: registrable + "." + tld,
        ruta: url.pathname || "/"
      },
      advice: adviceFor(level, signals)
    };
  }

  function isOfficialDomain(hostname, brand) {
    if (!brand.real) return false;
    return hostname === brand.real || hostname.slice(-(brand.real.length + 1)) === "." + brand.real;
  }

  function adviceFor(level, signals) {
    if (level === "alto") {
      return "No ingreses contraseñas, códigos ni datos bancarios en esta página. Verifica la dirección desde el sitio oficial de la empresa o contacta directamente por sus canales de atención.";
    }
    if (level === "med") {
      return "Antes de continuar, confirma que el dominio coincida con el oficial y evita introducir datos personales. Si el enlace llegó por mensaje, valida el aviso con la empresa por un canal distinto.";
    }
    if (signals.length > 0) {
      return "No se detectaron riesgos relevantes, pero revisa el enlace con atención. Recuerda que el candado HTTPS no garantiza que un sitio sea legítimo.";
    }
    return "No se encontraron señales conocidas de riesgo. Mantén tus hábitos de siempre: verifica el dominio y no compartas contraseñas desde enlaces recibidos por mensaje.";
  }

  var LEVEL_META = {
    alto: { label: "Riesgo alto", cls: "risk-high", meter: 88 },
    med: { label: "Riesgo medio", cls: "risk-med", meter: 55 },
    bajo: { label: "Riesgo bajo", cls: "risk-low", meter: 18 }
  };

  var SEVERITY_LABEL = { alto: "Alto", med: "Medio", bajo: "Bajo" };

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /* ---------- Interfaz ---------- */

  var form = document.getElementById("demo-form");
  var input = document.getElementById("url-input");
  var result = document.getElementById("demo-result");

  function renderError(message) {
    result.innerHTML =
      '<div class="demo-empty">' +
      '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>' +
      "<p>" + escapeHtml(message) + "</p>" +
      "</div>";
  }

  function renderResult(data) {
    var meta = LEVEL_META[data.level];
    var signalHtml;

    if (data.signals.length === 0) {
      signalHtml =
        '<p class="signal-none">No se encontraron señales de riesgo con las reglas actuales de este prototipo.</p>';
    } else {
      signalHtml = '<ul class="signal-list">' + data.signals.map(function (item) {
        return (
          "<li>" +
          '<span class="tag tag-' + (item.severity === "alto" ? "high" : item.severity === "med" ? "med" : "low") + '">' +
          SEVERITY_LABEL[item.severity] +
          "</span>" +
          '<span class="signal-text"><strong>' + escapeHtml(item.title) + "</strong><span>" +
          escapeHtml(item.detail) + "</span></span>" +
          "</li>"
        );
      }).join("") + "</ul>";
    }

    var partsHtml = '<dl class="parts-table">' +
      row("Protocolo", data.parts.protocolo) +
      row("Dominio", data.parts.dominio) +
      row("Host completo", data.parts.host) +
      row("Ruta", data.parts.ruta) +
      "</dl>";

    result.innerHTML =
      '<div class="result-head">' +
      '<span class="risk-badge ' + meta.cls + '">' + meta.label + "</span>" +
      "<h3>Resultado del análisis</h3>" +
      '<span class="result-url">' + escapeHtml(data.input) + "</span>" +
      "</div>" +
      '<div class="risk-meter"><span class="' + meta.cls + '" style="width:' +
      Math.min(meta.meter + data.signals.length * 3, 100) + '%"></span></div>' +
      '<div class="result-grid">' +
      '<div class="result-block"><h4>Señales encontradas (' + data.signals.length + ")</h4>" +
      signalHtml + "</div>" +
      '<div class="result-block"><h4>Estructura de la dirección</h4>' + partsHtml +
      '<div class="advice-box"><strong>Recomendación</strong>' + escapeHtml(data.advice) + "</div>" +
      "</div></div>" +
      '<div class="feedback" id="feedback">' +
      "<span>¿Te resultó útil esta advertencia?</span>" +
      '<button type="button" data-val="si">Sí, fue útil</button>' +
      '<button type="button" data-val="no">No, el sitio es legítimo</button>' +
      "</div>";

    var feedback = document.getElementById("feedback");
    feedback.addEventListener("click", function (event) {
      var button = event.target.closest("button[data-val]");
      if (!button) return;
      var buttons = feedback.querySelectorAll("button");
      for (var i = 0; i < buttons.length; i++) buttons[i].classList.remove("is-selected");
      button.classList.add("is-selected");
      var thanks = feedback.querySelector(".feedback-thanks");
      if (!thanks) {
        thanks = document.createElement("span");
        thanks.className = "feedback-thanks";
        feedback.appendChild(thanks);
      }
      thanks.textContent = "Gracias, tu respuesta se registra en esta sesión.";
    });
  }

  function row(label, value) {
    return (
      '<div class="parts-row"><dt>' + escapeHtml(label) + "</dt><dd>" +
      escapeHtml(value) + "</dd></div>"
    );
  }

  function runAnalysis() {
    var data = analyze(input.value);

    if (data.error) {
      input.classList.add("is-invalid");
      renderError(data.error);
      return;
    }

    input.classList.remove("is-invalid");
    renderResult(data);
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    runAnalysis();
  });

  input.addEventListener("input", function () {
    input.classList.remove("is-invalid");
  });

  document.querySelectorAll(".chip[data-url]").forEach(function (chip) {
    chip.addEventListener("click", function () {
      input.value = chip.getAttribute("data-url");
      runAnalysis();
      document.getElementById("demo").scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });

  /* ---------- Menú móvil ---------- */

  var toggle = document.getElementById("nav-toggle");
  var header = document.querySelector(".site-header");

  toggle.addEventListener("click", function () {
    var open = header.classList.toggle("nav-open");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  });

  document.querySelectorAll(".site-nav a").forEach(function (link) {
    link.addEventListener("click", function () {
      header.classList.remove("nav-open");
      toggle.setAttribute("aria-expanded", "false");
    });
  });
})();
