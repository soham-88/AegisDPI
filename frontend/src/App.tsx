import { useAegisStore } from "@/hooks/useAegisStore";
import { Dashboard } from "@/pages/Dashboard";
import { LoginPage } from "@/pages/LoginPage";

function App() {
  const { isAuthenticated } = useAegisStore();

  return isAuthenticated ? <Dashboard /> : <LoginPage />;
}

export default App;
