document.addEventListener('DOMContentLoaded', function() {
    // Handle buying players
    document.querySelectorAll('.buy-player').forEach(button => {
        button.addEventListener('click', async function() {
            const playerId = this.dataset.playerId;
            try {
                const response = await fetch('/unlimited/buy_player', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ player_id: playerId })
                });
                
                const data = await response.json();
                if (data.success) {
                    alert('Player purchased successfully!');
                    window.location.reload();
                } else {
                    alert(data.message || 'Failed to purchase player');
                }
            } catch (error) {
                console.error('Error:', error);
                alert('An error occurred while purchasing the player');
            }
        });
    });

    // Admin functionality for adding players
    const addPlayerForm = document.getElementById('addPlayerForm');
    if (addPlayerForm) {
        addPlayerForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData();
            formData.append('name', document.getElementById('playerName').value);
            formData.append('position', document.getElementById('position').value);
            formData.append('rating', document.getElementById('rating').value);
            formData.append('club', document.getElementById('club').value);
            formData.append('price', document.getElementById('price').value);
            
            const imageFile = document.getElementById('playerImage').files[0];
            if (imageFile) {
                formData.append('image', imageFile);
            }

            try {
                const response = await fetch('/unlimited/add_player', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                if (data.success) {
                    alert('Player added successfully!');
                    window.location.reload();
                } else {
                    alert(data.message || 'Failed to add player');
                }
            } catch (error) {
                console.error('Error:', error);
                alert('An error occurred while adding the player');
            }
        });
    }
});
