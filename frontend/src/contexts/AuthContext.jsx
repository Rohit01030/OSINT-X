import { createContext, useContext, useState, useEffect } from "react";
import { getCurrentUser, loginUser, registerUser } from "../services/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(() => localStorage.getItem("osintx_token"));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadUser() {
      if (token) {
        try {
          const userData = await getCurrentUser();
          setUser(userData);
        } catch (err) {
          console.error("Failed to load user profile:", err);
          logout();
        }
      } else {
        setUser(null);
      }
      setLoading(false);
    }
    loadUser();
  }, [token]);

  const login = async (usernameOrEmail, password) => {
    const res = await loginUser({ username_or_email: usernameOrEmail, password });
    if (res && res.access_token) {
      localStorage.setItem("osintx_token", res.access_token);
      setToken(res.access_token);
      const userData = await getCurrentUser();
      setUser(userData);
      return userData;
    }
  };

  const register = async (username, email, password) => {
    const res = await registerUser({ username, email, password });
    // After registration, auto-login
    return await login(username, password);
  };

  const logout = () => {
    localStorage.removeItem("osintx_token");
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
