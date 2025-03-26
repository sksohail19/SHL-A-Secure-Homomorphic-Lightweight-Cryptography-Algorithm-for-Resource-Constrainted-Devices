class EncryptionProcess {
    static s_box = {
        "0000": "0101", "0001": "0111", "0010": "1101", "0011": "1001",
        "0100": "1011", "0101": "1110", "0110": "1100", "0111": "1010",
        "1000": "1111", "1001": "0010", "1010": "0100", "1011": "0001",
        "1100": "1000", "1101": "0000", "1110": "0110", "1111": "0011"
    };

    static encrypt(text, IK, salt) {
        const L = 16;
        const info = "OutputKey_";

        const binary_str = Array.from(text).map(char => 
            char.charCodeAt(0).toString(2).padStart(8, '0')
        ).join('');

        const PRK = this.HKDF_Extract(IK, salt);
        const output_keys = this.HKDF_Expand(PRK, info, L, 7);
        
        let k = 0;
        let string = "";
        while (k < binary_str.length) {
            let mat = Array.from({length: 16}, () => Array(8).fill(0));
            
            for (let i = 0; i < 16; i++) {
                for (let j = 0; j < 8; j++) {
                    if (k < binary_str.length) {
                        mat[i][j] = parseInt(binary_str[k]);
                        k++;
                    }
                }
            }

            let transposed_matrix = mat[0].map((_, colIndex) => mat.map(row => row[colIndex]));
            
            for (let i = 0; i < 7; i++) {
                transposed_matrix = this.permutation_matrix(transposed_matrix);
                transposed_matrix = this.substitution_matrix(transposed_matrix);
                transposed_matrix = this.transformation_matrix(transposed_matrix);
                transposed_matrix = this.function_box(i, IK, salt, info, L, transposed_matrix, output_keys[i]);
                transposed_matrix = this.permutation_matrix(transposed_matrix);
            }

            for (let i = 0; i < 8; i++) {
                for (let j = 0; j < 16; j++) {
                    string += transposed_matrix[i][j];
                }
            }
        }

        return this.binary_to_text(string);
    }

    static HKDF_Extract(IK, salt) {
        // Simple HMAC with SHA-256 simulation
        return btoa(IK + salt);
    }

    static HKDF_Expand(PRK, info, L, num_keys) {
        let output_key = [];
        let T = "";
        for (let i = 0; i < num_keys; i++) {
            T = btoa(PRK + info + (i + 1));
            output_key.push(T.slice(0, L));
        }
        return output_key;
    }

    static shift_up(matrix) {
        let shifted = [...matrix];
        shifted.push(shifted.shift());
        return shifted;
    }

    static shift_right(matrix) {
        return matrix.map(row => {
            let newRow = [...row];
            newRow.unshift(newRow.pop());
            return newRow;
        });
    }

    static permutation_matrix(matrix) {
        matrix = this.shift_up(matrix);
        matrix = this.shift_right(matrix);
        matrix = this.shift_up(matrix);
        return matrix;
    }

    static substitution_matrix(matrix) {
        for (let i = 0; i < 16; i++) {
            let string1 = matrix.slice(0, 4).map(row => row[i]).join('');
            let string2 = matrix.slice(4).map(row => row[i]).join('');
            
            let replaced1 = this.s_box[string1];
            let replaced2 = this.s_box[string2];
            
            for (let h = 0; h < 4; h++) {
                matrix[h][i] = parseInt(replaced1[h]);
                matrix[h + 4][i] = parseInt(replaced2[h]);
            }
        }
        return matrix;
    }

    static transformation_matrix(matrix) {
        return matrix.map(row => row.map(val => 1 - val));
    }

    static function_box(i, IK, salt, info, L, matrix, output_key) {
        const key_binary_str = Array.from(output_key)
            .map(char => char.charCodeAt(0).toString(2).padStart(8, '0'))
            .join('');
        
        const key_matrix = [];
        for (let i = 0; i < matrix.length; i++) {
            key_matrix.push(key_binary_str.slice(i * matrix[0].length, (i + 1) * matrix[0].length)
                .split('')
                .map(Number));
        }

        matrix = matrix.map((row, i) => 
            row.map((val, j) => val ^ key_matrix[i][j])
        );

        return this.transformation_matrix(matrix);
    }

    static binary_to_text(binary_string) {
        return binary_string.match(/.{1,8}/g)
            .map(byte => String.fromCharCode(parseInt(byte, 2)))
            .join('');
    }
}

class DecryptionProcess {
    static s_box = {
        "0000": "1101", "0001": "1011", "0010": "1001", "0011": "1111",
        "0100": "1010", "0101": "0000", "0110": "1110", "0111": "0001",
        "1000": "1100", "1001": "0011", "1010": "0111", "1011": "0100",
        "1100": "0110", "1101": "0010", "1110": "0101", "1111": "1000"
    };

    static decrypt(text, IK, salt) {
        const L = 16;
        const info = "OutputKey_";

        const binary_str = Array.from(text).map(char => 
            char.charCodeAt(0).toString(2).padStart(8, '0')
        ).join('');

        const PRK = this.HKDF_Extract(IK, salt);
        const output_keys = this.HKDF_Expand(PRK, info, L, 7);
        
        let k = 0;
        let string = "";
        while (k < binary_str.length) {
            let transposed_matrix = Array.from({length: 8}, () => Array(16).fill(0));
            
            for (let i = 0; i < 8; i++) {
                for (let j = 0; j < 16; j++) {
                    if (k < binary_str.length) {
                        transposed_matrix[i][j] = parseInt(binary_str[k]);
                        k++;
                    }
                }
            }

            let h = 6;
            for (let i = 0; i < 7; i++) {
                transposed_matrix = this.permutation_matrix(transposed_matrix);
                transposed_matrix = this.function_box(transposed_matrix, output_keys[h]);
                h--;
                transposed_matrix = this.transformation_matrix(transposed_matrix);
                transposed_matrix = this.substitution_matrix(transposed_matrix);
                transposed_matrix = this.permutation_matrix(transposed_matrix);
            }

            for (let i = 0; i < 16; i++) {
                for (let j = 0; j < 8; j++) {
                    string += transposed_matrix[j][i];
                }
            }
        }

        return this.binary_to_text(string);
    }

    // Reused methods from EncryptionProcess with similar implementations
    static HKDF_Extract = EncryptionProcess.HKDF_Extract;
    static HKDF_Expand = EncryptionProcess.HKDF_Expand;
    static binary_to_text = EncryptionProcess.binary_to_text;

    static shift_down(matrix) {
        let shifted = [...matrix];
        shifted.unshift(shifted.pop());
        return shifted;
    }

    static shift_left(matrix) {
        return matrix.map(row => {
            let newRow = [...row];
            newRow.push(newRow.shift());
            return newRow;
        });
    }

    static permutation_matrix(matrix) {
        matrix = this.shift_down(matrix);
        matrix = this.shift_left(matrix);
        matrix = this.shift_down(matrix);
        return matrix;
    }

    static substitution_matrix(matrix) {
        for (let i = 0; i < 16; i++) {
            let string1 = matrix.slice(0, 4).map(row => row[i]).join('');
            let string2 = matrix.slice(4).map(row => row[i]).join('');
            
            let replaced1 = this.s_box[string1];
            let replaced2 = this.s_box[string2];
            
            for (let h = 0; h < 4; h++) {
                matrix[h][i] = parseInt(replaced1[h]);
                matrix[h + 4][i] = parseInt(replaced2[h]);
            }
        }
        return matrix;
    }

    static transformation_matrix(matrix) {
        return matrix.map(row => row.map(val => 1 - val));
    }

    static function_box(matrix, output_key) {
        matrix = this.transformation_matrix(matrix);
        
        const key_binary_str = Array.from(output_key)
            .map(char => char.charCodeAt(0).toString(2).padStart(8, '0'))
            .join('');
        
        const key_matrix = [];
        for (let i = 0; i < matrix.length; i++) {
            key_matrix.push(key_binary_str.slice(i * matrix[0].length, (i + 1) * matrix[0].length)
                .split('')
                .map(Number));
        }

        matrix = matrix.map((row, i) => 
            row.map((val, j) => val ^ key_matrix[i][j])
        );

        return matrix;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const encryptSection = document.getElementById('encryptSection');
    const decryptSection = document.getElementById('decryptSection');
    const encryptForm = document.getElementById('encryptForm');
    const decryptForm = document.getElementById('decryptForm');
    const encryptResult = document.getElementById('encryptResult');
    const decryptResult = document.getElementById('decryptResult');

    // Mode switching
    encryptBtn.addEventListener('click', () => {
        encryptBtn.classList.add('active');
        decryptBtn.classList.remove('active');
        encryptSection.classList.add('active');
        decryptSection.classList.remove('active');
    });

    decryptBtn.addEventListener('click', () => {
        decryptBtn.classList.add('active');
        encryptBtn.classList.remove('active');
        decryptSection.classList.add('active');
        encryptSection.classList.remove('active');
    });

    // Function to create and manage copy functionality
    function createCopyButton(resultElement) {
        // Remove any existing copy button
        const existingCopyBtn = resultElement.querySelector('.copy-btn');
        if (existingCopyBtn) {
            existingCopyBtn.remove();
        }

        // Create copy button
        const copyBtn = document.createElement('button');
        copyBtn.textContent = 'Copy';
        copyBtn.classList.add('copy-btn');
        copyBtn.style.marginLeft = '10px';
        
        copyBtn.addEventListener('click', () => {
            // Extract the text content after the colon
            const textToCopy = resultElement.textContent.split(': ')[1];
            
            // Use Clipboard API to copy text
            navigator.clipboard.writeText(textToCopy).then(() => {
                // Temporary visual feedback
                copyBtn.textContent = 'Copied!';
                copyBtn.style.backgroundColor = '#28a745';
                
                setTimeout(() => {
                    copyBtn.textContent = 'Copy';
                    copyBtn.style.backgroundColor = '';
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy text: ', err);
                alert('Failed to copy text');
            });
        });

        resultElement.appendChild(copyBtn);
    }

    // Encryption
    encryptForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const plainText = document.getElementById('plainText').value;
        const secretMessage = document.getElementById('secretMessage').value;
        const saltMessage = document.getElementById('saltMessage').value;

        try {
            const ciphertext = EncryptionProcess.encrypt(plainText, secretMessage, saltMessage);
            encryptResult.textContent = `Ciphertext: ${ciphertext}`;
            
            // Add copy button
            createCopyButton(encryptResult);
        } catch (error) {
            encryptResult.textContent = `Encryption Error: ${error.message}`;
        }
    });

    // Decryption
    decryptForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const cipherText = document.getElementById('cipherText').value;
        const secretMessage = document.getElementById('decryptSecretMessage').value;
        const saltMessage = document.getElementById('decryptSaltMessage').value;

        try {
            const plaintext = DecryptionProcess.decrypt(cipherText, secretMessage, saltMessage);
            decryptResult.textContent = `Plaintext: ${plaintext}`;
            
            // Add copy button
            createCopyButton(decryptResult);
        } catch (error) {
            decryptResult.textContent = `Decryption Error: ${error.message}`;
        }
    });
});