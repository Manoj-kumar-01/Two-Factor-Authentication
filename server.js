const express = require('express');
const speakeasy = require('speakeasy');
const uuid = require('uuid');
const { JsonDB } = require('node-json-db');
const { Config } = require('node-json-db/dist/lib/JsonDBConfig');

const PORT = process.env.PORT || 3000;
const app = express();
app.use(express.json());

const db = new JsonDB(new Config("myDataBase", true, false, '/'));


app.get('/api', (req, res) => {
    res.json({ message: "Welcome to the Two Factor Authentication" });
});


app.post('/api/register', (req, res) => {
    const id = uuid.v4();
    try {
        const path = `/user/${id}`;
        const temp_secret = speakeasy.generateSecret();
        db.push(path, { id, temp_secret });
        res.json({ id, secret: temp_secret.base32 });
        console.log("Registered user:", { id, temp_secret });
    } catch (err) {
        console.error("Error registering user:", err.message);
        res.status(500).json({ message: 'Error generating secret' });
    }
});


app.post('/api/verify', async (req, res) => {
    const { token, userId } = req.body;

    if (!token || !userId) {
        return res.status(400).json({ message: "Token and userId are required." });
    }

    try {
        const path = `/user/${userId}`;
        console.log("Database path:", path);
        if (!db.exists(path)) {
            console.error("User not found for userId:", userId);
            return res.status(404).json({ message: `User with ID ${userId} not found.` });
        }

        const user = await db.getData(path);

        console.log("User data:", user);
        
        if (!user || !user.temp_secret) {
            console.error("Temp secret is missing for user:", userId);
            return res.status(400).json({ message: "Invalid or missing temp secret." });
        }

        const { base32: secret } = user.temp_secret;
    
        console.log("Secret used for verification:", secret);
       
        const tokenValidates = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token,
            window: 1 
        });

        if (tokenValidates) {
            
            await db.push(path, { id: userId, secret: user.temp_secret });
            return res.json({ validated: true });
        } else {
            return res.json({ validated: false });
        }
    } catch (err) {
        console.error("Verification error:", err.message);
        res.status(500).json({ message: "Internal server error." });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running at PORT ${PORT}`);
});