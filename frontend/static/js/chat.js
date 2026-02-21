
let socket = io();
let activeRoom = null;

function openRoom(roomId, name) {

    activeRoom = roomId;

    document.getElementById("room-header").innerText = name;
    document.getElementById("messages").innerHTML = "";

    socket.emit("join", {
        room: roomId,
        user: CURRENT_USER_NAME
    });

    fetch(`/api/chat/${roomId}/messages`)
        .then(r => r.json())
        .then(data => {
            data.forEach(addMessage);
        });
}

function addMessage(m) {
    const messagesDiv = document.getElementById("messages");

    const wrapper = document.createElement("div");
    wrapper.classList.add("message");

    if (m.user_id === CURRENT_USER_ID)
        wrapper.classList.add("me");
    else
        wrapper.classList.add("other");

    wrapper.innerHTML = `
        <div class="sender">${m.user_name}</div>
        <div>${m.content}</div>
    `;

    messagesDiv.appendChild(wrapper);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function sendMessage() {

    const input = document.getElementById("message-input");

    socket.emit("send_message", {
        room: activeRoom,
        content: input.value,
        user_id: CURRENT_USER_ID,
        user_name: CURRENT_USER_NAME,
    });

    input.value = "";
}

socket.on("receive_message", function(data) {
    addMessage(data);
});
