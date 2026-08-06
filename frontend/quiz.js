// SentinelSEBI — Quiz Module
// Interactive investor awareness quiz

function initQuiz() {
  currentQuizIdx = 0;
  renderQuizQuestion();
}

function renderQuizQuestion() {
  const q = quizData[currentQuizIdx];
  document.getElementById('quiz-question-txt').innerText = `Q${currentQuizIdx+1}: ${q.q}`;
  
  const container = document.getElementById('quiz-options-container');
  container.innerHTML = q.options.map((opt, i) => `
    <div class="quiz-option" onclick="submitQuizAnswer(${i}, this)">${opt.text}</div>
  `).join('');
  
  document.getElementById('quiz-next-btn').style.display = 'none';
}

function submitQuizAnswer(optIdx, element) {
  const q = quizData[currentQuizIdx];
  const optionSelected = q.options[optIdx];
  
  // Highlight correct & incorrect options
  const options = document.querySelectorAll('.quiz-option');
  options.forEach((el, index) => {
    // disable clicking again
    el.onclick = null;
    if (q.options[index].correct) {
      el.classList.add('correct');
    } else if (index === optIdx) {
      el.classList.add('incorrect');
    }
  });

  if (optionSelected.correct) {
    showToast("Correct Answer! Be aware, stay safe.");
  } else {
    showToast("Incorrect. Learn the safety rules to secure your investments.");
  }

  document.getElementById('quiz-next-btn').style.display = 'inline-block';
}

function nextQuizQuestion() {
  currentQuizIdx = (currentQuizIdx + 1) % quizData.length;
  renderQuizQuestion();
}
