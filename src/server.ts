import 'dotenv/config';
import app from "./app";

const PORT = Number(process.env.PORT) || 3000;

app.get("/", (req, res) => {
  res.send("Welcome to the Auth Service!");
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
});

