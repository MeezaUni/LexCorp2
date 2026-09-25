import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from './context/AuthContext';
import Dashboard from './pages/Dashboard';
import Verify from './pages/Verify';
import VerifyAction from './pages/VerifyAction';

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/verify/:serial" element={<Verify />} />
            <Route path="/verify/token/:tokenId" element={<Verify />} />
            <Route path="/verify/action/:actionId" element={<VerifyAction />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
