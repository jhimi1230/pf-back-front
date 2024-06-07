const Mongoose = require("mongoose");

const TodoSchema = new Mongoose.Schema({
  id: { type: Object },
  idUser: { type: String, required: true },
  data: { type: String, required: true },
  tipohash: { type: String, required: true },
  hash: { type: String, required: true }
});

module.exports = Mongoose.model("Todo", TodoSchema);
