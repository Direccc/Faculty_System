window.onload = function() {
    const dataElement = document.getElementById('messages-data');
    if (!dataElement) return; // no messages to show

    const messages = JSON.parse(dataElement.textContent);
    const toast = document.getElementById("toast");

    messages.forEach(function(message) {
        // Get message text and type
        let messageText = message.message; // <- correct, Django gives 'message'
        let messageType = message.tags;     // <- correct, Django gives 'tags'

        // Display the message in the toast
        toast.innerText = messageText;

        // Add error class if it's an error message
        if (messageType.includes('error')) {
            toast.classList.add("error");
        } else {
            toast.classList.remove("error");
        }

        // Show the toast
        toast.style.visibility = "visible";

        // Hide the toast after 3 seconds
        setTimeout(() => {
            toast.style.visibility = "hidden";
            toast.classList.remove("error"); // Remove error class after hiding
        }, 3000);
    });
};


function checkPasswordStrength() {
    const password = document.getElementById("new_password").value;
    const message = document.getElementById("password-strength-message");
    const bar = document.getElementById("password-strength-bar");
  
    const rules = [
      { regex: /[A-Z]/, message: "Uppercase letter" },
      { regex: /[a-z]/, message: "Lowercase letter" },
      { regex: /[0-9]/, message: "Number" },
      { regex: /[!@#$%^&*(),.?\":{}|<>]/, message: "Special character" },
      { regex: /.{8,}/, message: "At least 8 characters" },
    ];
  
    let passed = 0;
    let feedback = rules.map(rule => {
      const passedRule = rule.regex.test(password);
      if (passedRule) passed++;
      return passedRule
        ? `<span style="color: green;">✔ ${rule.message}</span>`
        : `<span style="color: red;">✖ ${rule.message}</span>`;
    });
  
    message.innerHTML = feedback.join("<br>");
    const strengthPercent = (passed / rules.length) * 100;
    bar.style.width = `${strengthPercent}%`;
  
    if (passed <= 2) {
      bar.style.backgroundColor = "red";
    } else if (passed === 3 || passed === 4) {
      bar.style.backgroundColor = "orange";
    } else if (passed === 5) {
      bar.style.backgroundColor = "green";
    }
  }