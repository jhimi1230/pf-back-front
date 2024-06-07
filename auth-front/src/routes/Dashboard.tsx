import React, { useEffect, useState } from "react";
import PortalLayout from "../layout/PortalLayout";
import { useAuth } from "../auth/AuthProvider";
import { API_URL } from "../auth/authConstants";

interface Todo {
  id: string;
  data: string;
  tipohash: string;
  hash: string;
}

export default function Dashboard() {
  const auth = useAuth();
  const [todos, setTodos] = useState<Todo[]>([]);
  const [value, setValue] = useState("");
  const [selectedOption, setSelectedOption] = useState("Datos en Reposo");

  async function getTodos() {
    const accessToken = auth.getAccessToken();
    try {
      const response = await fetch(`${API_URL}/posts`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (response.ok) {
        const json = await response.json();
        setTodos(json);
        console.log(json);
      }
    } catch (error) {
      console.log(error);
    }
  }

  async function createTodo() {
    if (value.length > 3) {
      try {
        const response = await fetch(`${API_URL}/posts`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${auth.getAccessToken()}`,
          },
          body: JSON.stringify({ data: value, tipohash: selectedOption }),
        });
        if (response.ok) {
          const todo = (await response.json()) as Todo;
          setTodos([...todos, todo]);
        }
      } catch (error) { }
    }
  }

  useEffect(() => {
    getTodos();
  }, []);

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    createTodo();
  }

  return (
    <PortalLayout>
      <div className="dashboard">
        <h1>Dashboard de {auth.getUser()?.name ?? ""}</h1>
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="New task to do..."
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
          <select value={selectedOption} onChange={(e) => setSelectedOption(e.target.value)}>
            <option value="">Select an option</option>
            <option value="Datos en Reposo">Datos en Reposo</option>
            <option value="Almacenamiento Seguro de Contraseña">Almacenamiento Seguro de Contraseña</option>
            <option value="Firma Digital">Firma Digital</option>
            <option value="Autenticidad de Datos">Autenticidad de Datos</option>
          </select>
          <button type="submit">Guardar</button>
        </form>
        {todos.map((post: Todo) => (
          <div key={post.id} style={{ marginBottom: '10px', borderBottom: '1px solid black' }}>
            <h3>Tipo de operacion: {post.tipohash}</h3>
            <h3>  data: {post.data}</h3>
            <h3>  hash: {post.hash}</h3>
          </div>
        ))}
      </div>
    </PortalLayout>
  );
}