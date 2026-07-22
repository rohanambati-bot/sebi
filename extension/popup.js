document.getElementById("check").addEventListener("click", async () => {
  const code = document.getElementById("code").value.trim();
  const resultBox = document.getElementById("result");
  if (!code) {
    resultBox.innerText = "Please enter a printed Sentinel verify-code.";
    resultBox.style.display = "block";
    resultBox.style.color = "#ef4444";
    return;
  }
  
  resultBox.innerText = "Checking registry...";
  resultBox.style.display = "block";
  resultBox.style.color = "#9ca3af";
  
  try {
    const res = await fetch(`http://127.0.0.1:8000/verify/by-code`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code })
    });
    const data = await res.json();
    if (data.status === "VERIFIED") {
      resultBox.style.color = "#10b981";
      resultBox.innerHTML = `✅ <b>VERIFIED AUTHENTIC</b><br>
      Issuer: <b>${data.issuer}</b><br>
      Channel: ${data.channel}<br>
      Domain: <code>${data.source_domain}</code>`;
    } else {
      resultBox.style.color = "#ef4444";
      resultBox.innerHTML = `⚠️ <b>${data.status.replace(/_/g,' ')}</b><br>
      ${data.message}`;
    }
  } catch(e) {
    resultBox.style.color = "#ef4444";
    resultBox.innerText = "Sentinel API connection failed. Ensure local backend is running on port 8000.";
  }
});
