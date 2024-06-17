document.addEventListener('DOMContentLoaded', function() {
    const fetchTrendingPairsButton = document.getElementById('fetch-trending-pairs-button');
    
    const fetchTrendingPairs = async () => {
        const query = document.getElementById('query').value || 'BTC';
        const network = document.getElementById('network').value.toUpperCase();
        
        console.log('Fetching with query:', query, 'and network:', network);  // Debug log

        try {
            const response = await fetch(`/admin/quantumapp/tokenpair/fetch-trending-pairs/?q=${query}&network=${network}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
                }
            });

            console.log('Response status:', response.status);  // Debug log
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log('Response data:', data);  // Debug log
            
            const resultDiv = document.getElementById('fetch-result');
            if (data.status === 'success') {
                console.log('Fetched tokens:', data.tokens); // Print fetched tokens
                if (data.tokens.length === 0) {
                    resultDiv.innerHTML = `<p style="color: red;">No tokens fetched, possibly no matching data.</p>`;
                } else {
                    // Validate and convert fetched tokens
                    const validatedTokens = data.tokens.map(validateAndConvertTokenData);
                    resultDiv.innerHTML = `<p style="color: green;">${data.message}</p><pre>${JSON.stringify(validatedTokens, null, 2)}</pre>`;
                }
            } else {
                resultDiv.innerHTML = `<p style="color: red;">${data.message}</p>`;
            }
        } catch (error) {
            console.error('Fetch error:', error);  // Debug log
            document.getElementById('fetch-result').innerHTML = `<p style="color: red;">Fetch error: ${error.message}</p>`;
        }
    };

    const validateAndConvertTokenData = (token) => {
        const scientificNotationRegex = /^-?\d+(\.\d+)?([eE][-+]?\d+)?$/;

        const formatToScientific = (value) => {
            return Number(value).toExponential(6);
        };

        const validateAndConvertField = (field) => {
            if (scientificNotationRegex.test(field)) {
                return formatToScientific(field);
            } else if (!isNaN(field)) {
                return formatToScientific(field);
            }
            return field;
        };

        // Validate and convert numerical fields in token data
        if (token.priceNative) token.priceNative = validateAndConvertField(token.priceNative);
        if (token.priceUsd) token.priceUsd = validateAndConvertField(token.priceUsd);
        if (token.volume) {
            for (const key in token.volume) {
                token.volume[key] = validateAndConvertField(token.volume[key]);
            }
        }
        if (token.liquidity) {
            for (const key in token.liquidity) {
                token.liquidity[key] = validateAndConvertField(token.liquidity[key]);
            }
        }

        return token;
    };

    fetchTrendingPairsButton.addEventListener('click', fetchTrendingPairs);
});
