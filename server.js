const express = require('express');
const path = require('path');
const app = express();
app.use(express.static(path.join(__dirname, 'عام')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'عام', 'index.html'));
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Running'));
