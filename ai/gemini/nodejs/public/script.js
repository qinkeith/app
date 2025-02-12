async function sendQuestion() {
    const questionInput = document.getElementById('questionInput');
    const question = questionInput.value.trim();

    if (!question) {
        alert('Please enter a question.');
        return;
    }

    // Display user's question in the chat
    const chatDiv = document.getElementById('chat');
    const userMessage = document.createElement('div');
    userMessage.classList.add('message', 'user-message');
    userMessage.textContent = question; // User message is plain text
    chatDiv.appendChild(userMessage);

    // Clear the input
    questionInput.value = '';

    try {
        // Send the question to the backend
        const response = await fetch('/gemini', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ question }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Failed to fetch response from Gemini.");
        }

        const data = await response.json();
        const geminiResponse = data.response;

        // Display Gemini's response in the chat as HTML
        const geminiMessage = document.createElement('div');
        geminiMessage.classList.add('message', 'gemini-message');
        geminiMessage.innerHTML = geminiResponse; // Use innerHTML to render HTML
        chatDiv.appendChild(geminiMessage);

        // Scroll to the bottom of the chat
        chatDiv.scrollTop = chatDiv.scrollHeight;
    } catch (error) {
        console.error('Error:', error);
        const errorMessage = document.createElement('div');
        errorMessage.classList.add('message', 'error-message');
        errorMessage.textContent = `Error: ${error.message}`;
        chatDiv.appendChild(errorMessage);
        chatDiv.scrollTop = chatDiv.scrollHeight;
    }
}