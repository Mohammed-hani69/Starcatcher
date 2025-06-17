document.addEventListener('DOMContentLoaded', function() {
    // Initialize the football field with formation positions
    const formation = {
        'GK': [{x: 50, y: 90}],
        'DEF': [{x: 20, y: 70}, {x: 40, y: 70}, {x: 60, y: 70}, {x: 80, y: 70}],
        'MID': [{x: 30, y: 50}, {x: 50, y: 50}, {x: 70, y: 50}],
        'ATT': [{x: 30, y: 30}, {x: 50, y: 30}, {x: 70, y: 30}]
    };
    
    let selectedPlayer = null;
    let selectedPosition = null;
    
    function initializePositions() {
        const field = document.querySelector('.football-field');
        
        // Create position markers for each position in the formation
        Object.entries(formation).forEach(([position, spots]) => {
            spots.forEach((spot, index) => {
                const marker = document.createElement('div');
                marker.className = 'player-position';
                marker.dataset.position = position;
                marker.dataset.index = index;
                marker.style.left = `${spot.x}%`;
                marker.style.top = `${spot.y}%`;
                
                marker.addEventListener('click', handlePositionClick);
                field.appendChild(marker);
            });
        });
        
        // Load current team data
        loadTeamData();
    }
    
    async function loadTeamData() {
        try {
            const response = await fetch('/unlimited/get_team');
            const data = await response.json();
            
            if (data.success) {
                // Update positions with current players
                data.players.forEach(player => {
                    if (!player.is_substitute) {
                        updatePosition(player);
                    }
                });
                
                // Update substitutes bench
                updateSubstitutes(data.players.filter(p => p.is_substitute));
                
                // Update team info
                document.getElementById('teamPoints').textContent = data.team.points;
                updateSquadList(data.players);
            }
        } catch (error) {
            console.error('Error loading team data:', error);
        }
    }
    
    function updatePosition(player) {
        const position = document.querySelector(`.player-position[data-position="${player.position}"][data-index="${player.position_order}"]`);
        if (position) {
            position.classList.add('occupied');
            position.innerHTML = `
                <img src="${player.image_url}" alt="${player.name}">
                <div class="player-info">
                    ${player.name}<br>
                    Rating: ${player.rating}
                </div>
            `;
            position.dataset.playerId = player.id;
        }
    }
    
    function updateSubstitutes(substitutes) {
        const container = document.getElementById('substitutesContainer');
        container.innerHTML = '';
        
        substitutes.forEach(player => {
            const sub = document.createElement('div');
            sub.className = 'substitute-player';
            sub.innerHTML = `
                <img src="${player.image_url}" alt="${player.name}" style="width: 100%; height: 100%; border-radius: 50%;">
            `;
            sub.dataset.playerId = player.id;
            sub.addEventListener('click', handleSubstituteClick);
            container.appendChild(sub);
        });
    }
    
    function updateSquadList(players) {
        const list = document.getElementById('squadList');
        list.innerHTML = '';
        
        players.forEach(player => {
            const item = document.createElement('div');
            item.className = 'squad-player';
            item.innerHTML = `
                <small>${player.name} - ${player.position} (${player.rating})</small>
            `;
            list.appendChild(item);
        });
    }
    
    function handlePositionClick(e) {
        const position = e.currentTarget;
        
        if (selectedPlayer) {
            // Make substitution
            makeSubstitution(selectedPlayer, position);
            selectedPlayer = null;
            selectedPosition = null;
        } else if (position.classList.contains('occupied')) {
            // Show player details
            selectedPosition = position;
            showPlayerDetails(position.dataset.playerId);
        }
    }
    
    function handleSubstituteClick(e) {
        const sub = e.currentTarget;
        
        if (selectedPosition) {
            // Make substitution
            makeSubstitution(sub, selectedPosition);
            selectedPosition = null;
        } else {
            selectedPlayer = sub;
        }
    }
    
    async function makeSubstitution(fromElement, toElement) {
        try {
            const response = await fetch('/unlimited/make_substitution', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    player_id: fromElement.dataset.playerId,
                    new_position: toElement.dataset.position,
                    position_order: toElement.dataset.index
                })
            });
            
            const data = await response.json();
            if (data.success) {
                loadTeamData(); // Refresh the display
            } else {
                alert(data.message || 'Failed to make substitution');
            }
        } catch (error) {
            console.error('Error making substitution:', error);
            alert('An error occurred while making the substitution');
        }
    }
    
    async function showPlayerDetails(playerId) {
        try {
            const response = await fetch(`/unlimited/player_details/${playerId}`);
            const data = await response.json();
            
            if (data.success) {
                const modal = new bootstrap.Modal(document.getElementById('playerDetailsModal'));
                const detailsContainer = document.querySelector('.player-details');
                
                detailsContainer.innerHTML = `
                    <div class="text-center mb-3">
                        <img src="${data.player.image_url}" alt="${data.player.name}" style="width: 100px; height: 100px; border-radius: 50%;">
                    </div>
                    <h4>${data.player.name}</h4>
                    <p>Position: ${data.player.position}</p>
                    <p>Rating: ${data.player.rating}</p>
                    <p>Club: ${data.player.club}</p>
                    <h5>Recent Events:</h5>
                    <ul>
                        ${data.events.map(event => `
                            <li>${event.event_type} (${event.points > 0 ? '+' : ''}${event.points}) - ${event.match_info}</li>
                        `).join('')}
                    </ul>
                `;
                
                modal.show();
            }
        } catch (error) {
            console.error('Error loading player details:', error);
        }
    }
    
    // Initialize the field when the page loads
    initializePositions();
});
