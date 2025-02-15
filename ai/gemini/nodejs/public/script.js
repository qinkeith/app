async function sendQuestion() {
    const questionInput = document.getElementById('questionInput');
    const systemMessage = document.getElementById('systemMessage');
    const question = questionInput.value.trim();

    if (!question) {
        alert('Please enter a question.');
        return;
    }

    if (!systemMessage.value.trim()) {
        alert('Please enter a system message.');
        return;
    }

    // Display user's question in the chat
    const chatDiv = document.getElementById('chat');
    const userMessage = document.createElement('div');
    userMessage.classList.add('message', 'user-message');
    userMessage.textContent = question;
    chatDiv.appendChild(userMessage);

    // Clear the input
    questionInput.value = '';

    try {
        // Send the question and system message to the backend
        const response = await fetch('/gemini', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                question,
                systemMessage: systemMessage.value.trim()
            }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Failed to fetch response from Gemini.");
        }

        const data = await response.json();
        const geminiResponse = data.response;

        // Display Gemini's response in the chat
        const geminiMessage = document.createElement('div');
        geminiMessage.classList.add('message', 'gemini-message');
        geminiMessage.innerHTML = geminiResponse;
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
