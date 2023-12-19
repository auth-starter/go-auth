import { useState, useEffect } from "react";

import "./App.css";

function App() {
	const [data, setData] = useState(null);

	const queryParams = new URLSearchParams(window.location.search);
	const code = queryParams.get("code");
	const state = queryParams.get("state");

	useEffect(() => {
		"use-client";

		if (code) {
			fetch("http://localhost:8292/verify", {
				method: "POST",
				body: JSON.stringify({
					code,
          state
				}),

				// Adding headers to the request
				headers: {
					"Content-type": "application/json",
				},
			})
				.then((res) => {
					return res.json();
				})
				.then((data) => {
					setData(data);
					console.log(data);
				});
		}
	}, [code]);

	return (
		<>
			<h1>Vite + React</h1>
			<div className="card">
				<button onClick={() => {window.location.href="http://localhost:8292/auth"}}>
					Login
				</button>
				<p>
					code is <code>{code}</code>
				</p>
				{data && <h1>{JSON.stringify(data)}</h1>}
			</div>
		</>
	);
}

export default App;
