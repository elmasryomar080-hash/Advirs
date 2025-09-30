// popup.js - advirs popup script (عربي بالكامل)

document.addEventListener("DOMContentLoaded", () => {
  const statusEl = document.getElementById("status");
  const resultsEl = document.getElementById("results");

  function renderResult(data) {
    resultsEl.innerHTML = ""; // مسح النتائج القديمة

    if (!data || !data.result) {
      statusEl.innerText = "❌ لا يوجد تحليل حتى الآن.";
      return;
    }

    const { suspicious, score, reasons } = data.result;

    statusEl.innerText = suspicious
      ? `⚠️ تم اكتشاف نشاط مشبوه (${Math.round(score * 100)}٪)`
      : `✅ الصفحة آمنة (${Math.round(score * 100)}٪)`;

    const list = document.createElement("ul");
    list.style.paddingLeft = "20px";
    (reasons || []).slice(0, 10).forEach(r => {
      const li = document.createElement("li");
      li.innerText = r; // ممكن تترجم الأسباب في الـ background.js لو حبيت
      list.appendChild(li);
    });

    resultsEl.appendChild(list);
  }

  // تحميل نتيجة التحليل الحالية
  function loadCurrent() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || !tabs[0]) return;
      chrome.tabs.sendMessage(tabs[0].id, { type: "getPayload" }, (resp) => {
        if (!resp || !resp.payload) {
          statusEl.innerText = "⚠️ لا توجد بيانات مرسلة من الصفحة.";
          return;
        }
        chrome.runtime.sendMessage({ type: "analyzeProfile", data: resp.payload }, (analysis) => {
          if (analysis && analysis.result) {
            renderResult(analysis);
          } else {
            statusEl.innerText = "❌ لم يتم الحصول على نتيجة التحليل.";
          }
        });
      });
    });
  }

  loadCurrent();
});
