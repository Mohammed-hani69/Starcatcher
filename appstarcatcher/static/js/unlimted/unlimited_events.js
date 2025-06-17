document.addEventListener('DOMContentLoaded', function() {
    const playerSearchInput = document.getElementById('playerSearch');
    let selectedPlayerId = null;
    
    // Initialize player search autocomplete
    if (playerSearchInput) {
        let timeout = null;
        playerSearchInput.addEventListener('input', function() {
            clearTimeout(timeout);
            timeout = setTimeout(async function() {
                const searchTerm = playerSearchInput.value;
                if (searchTerm.length >= 2) {
                    try {
                        const response = await fetch(`/unlimited/search_players?q=${encodeURIComponent(searchTerm)}`);
                        const data = await response.json();
                        
                        if (data.success) {
                            showPlayerSuggestions(data.players);
                        }
                    } catch (error) {
                        console.error('Error searching players:', error);
                    }
                }
            }, 300);
        });
    }
    
    function showPlayerSuggestions(players) {
        let suggestionsDiv = document.getElementById('playerSuggestions');
        if (!suggestionsDiv) {
            suggestionsDiv = document.createElement('div');
            suggestionsDiv.id = 'playerSuggestions';
            suggestionsDiv.className = 'suggestions-container';
            playerSearchInput.parentNode.appendChild(suggestionsDiv);
        }
        
        suggestionsDiv.innerHTML = '';
        players.forEach(player => {
            const suggestion = document.createElement('div');
            suggestion.className = 'suggestion-item';
            suggestion.innerHTML = `${player.name} (${player.position})`;
            suggestion.addEventListener('click', () => {
                playerSearchInput.value = player.name;
                selectedPlayerId = player.id;
                suggestionsDiv.innerHTML = '';
            });
            suggestionsDiv.appendChild(suggestion);
        });
    }
    
    // Handle event form submission
    const addEventForm = document.getElementById('addEventForm');
    if (addEventForm) {
        addEventForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            if (!selectedPlayerId) {
                alert('Please select a player first');
                return;
            }
            
            const eventData = {
                player_id: selectedPlayerId,
                event_type: document.getElementById('eventType').value,
                match_info: document.getElementById('matchInfo').value
            };
            
            try {
                const response = await fetch('/unlimited/add_event', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(eventData)
                });
                
                const data = await response.json();
                if (data.success) {
                    alert('Event added successfully!');
                    // Clear form and refresh table
                    addEventForm.reset();
                    selectedPlayerId = null;
                    loadEvents();
                } else {
                    alert(data.message || 'Failed to add event');
                }
            } catch (error) {
                console.error('Error:', error);
                alert('An error occurred while adding the event');
            }
        });
    }
    
    // Handle event deletion
    document.addEventListener('click', async function(e) {
        if (e.target.classList.contains('delete-event')) {
            if (confirm('Are you sure you want to delete this event?')) {
                const eventId = e.target.dataset.eventId;
                try {
                    const response = await fetch(`/unlimited/delete_event/${eventId}`, {
                        method: 'DELETE'
                    });
                    
                    const data = await response.json();
                    if (data.success) {
                        e.target.closest('tr').remove();
                    } else {
                        alert(data.message || 'Failed to delete event');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    alert('An error occurred while deleting the event');
                }
            }
        }
    });
    
    async function loadEvents() {
        try {
            const response = await fetch('/unlimited/get_events');
            const data = await response.json();
            
            if (data.success) {
                const tbody = document.getElementById('eventsTableBody');
                tbody.innerHTML = data.events.map(event => `
                    <tr>
                        <td>${event.player.name}</td>
                        <td>${event.event_type}</td>
                        <td>${event.points}</td>
                        <td>${event.match_info}</td>
                        <td>${new Date(event.created_at).toLocaleString()}</td>
                        <td>
                            <button class="btn btn-danger btn-sm delete-event" data-event-id="${event.id}">
                                Delete
                            </button>
                        </td>
                    </tr>
                `).join('');
            }
        } catch (error) {
            console.error('Error loading events:', error);
        }
    }
    
    // Load events on page load
    loadEvents();
});
