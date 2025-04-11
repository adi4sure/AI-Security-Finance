// server.js (example backend)
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const app = express();
const upload = multer({ dest: 'uploads/' });

app.post('/api/scan', upload.single('file'), async(req, res) => {
    try {
        const formData = new FormData();
        formData.append('file', fs.createReadStream(req.file.path));

        const response = await axios.post('https://www.virustotal.com/api/v3/files', formData, {
            headers: {
                'x-apikey': process.env.VIRUSTOTAL_API_KEY,
                ...formData.getHeaders()
            }
        });

        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    } finally {
        fs.unlinkSync(req.file.path); // Clean up uploaded file
    }
});

app.listen(3000, () => console.log('Server running on port 3000'));