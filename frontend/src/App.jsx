import MainLayout from "./layouts/MainLayout.jsx";
import AppRoutes from "./routes/AppRoutes.jsx";

export default function App() {
  return (
    <MainLayout>
      <AppRoutes />
    </MainLayout>
  );
}