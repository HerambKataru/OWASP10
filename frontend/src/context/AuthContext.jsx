import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  auth,
  googleProvider,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  signInWithPopup
} from '../services/firebase';

const AuthContext = createContext(null);

export function useAuth() {
  return useContext(AuthContext);
}

export function AuthProvider({ children }) {
  const [currentUser, setCurrentUser] = useState(() => {
    const saved = localStorage.getItem('sentinelx_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!auth) {
      setLoading(false);
      return;
    }

    try {
      const unsubscribe = onAuthStateChanged(auth, (user) => {
        if (user) {
          const userData = {
            uid: user.uid,
            email: user.email,
            displayName: user.displayName || user.email?.split('@')[0] || 'Security Analyst',
            photoURL: user.photoURL || null,
            role: 'Senior Security Engineer'
          };
          setCurrentUser(userData);
          localStorage.setItem('sentinelx_user', JSON.stringify(userData));
        } else {
          // If no firebase user and no local demo user
          const saved = localStorage.getItem('sentinelx_user');
          if (!saved || !JSON.parse(saved).isDemo) {
            setCurrentUser(null);
            localStorage.removeItem('sentinelx_user');
          }
        }
        setLoading(false);
      });

      return unsubscribe;
    } catch (err) {
      console.warn("Auth listener fallback:", err);
      setLoading(false);
    }
  }, []);

  // Standard Email/Password Login
  const login = async (email, password) => {
    try {
      if (auth && !auth.app.options.apiKey.includes('Dummy')) {
        const result = await signInWithEmailAndPassword(auth, email, password);
        const userData = {
          uid: result.user.uid,
          email: result.user.email,
          displayName: result.user.displayName || email.split('@')[0],
          role: 'Senior Security Engineer'
        };
        setCurrentUser(userData);
        localStorage.setItem('sentinelx_user', JSON.stringify(userData));
        return userData;
      } else {
        // Local direct authentication fallback
        const userData = {
          uid: 'local_' + btoa(email).slice(0, 10),
          email: email,
          displayName: email.split('@')[0],
          role: 'Senior Security Engineer',
          isDemo: true
        };
        setCurrentUser(userData);
        localStorage.setItem('sentinelx_user', JSON.stringify(userData));
        return userData;
      }
    } catch (error) {
      // If Firebase fails with auth error or invalid API key, allow graceful local login
      if (error.code === 'auth/invalid-api-key' || error.code === 'auth/api-key-not-valid') {
        const userData = {
          uid: 'local_' + btoa(email).slice(0, 10),
          email: email,
          displayName: email.split('@')[0],
          role: 'Senior Security Engineer',
          isDemo: true
        };
        setCurrentUser(userData);
        localStorage.setItem('sentinelx_user', JSON.stringify(userData));
        return userData;
      }
      throw error;
    }
  };

  // Sign up
  const signup = async (email, password) => {
    try {
      if (auth && !auth.app.options.apiKey.includes('Dummy')) {
        const result = await createUserWithEmailAndPassword(auth, email, password);
        const userData = {
          uid: result.user.uid,
          email: result.user.email,
          displayName: email.split('@')[0],
          role: 'Security Analyst'
        };
        setCurrentUser(userData);
        localStorage.setItem('sentinelx_user', JSON.stringify(userData));
        return userData;
      } else {
        const userData = {
          uid: 'local_' + btoa(email).slice(0, 10),
          email: email,
          displayName: email.split('@')[0],
          role: 'Security Analyst',
          isDemo: true
        };
        setCurrentUser(userData);
        localStorage.setItem('sentinelx_user', JSON.stringify(userData));
        return userData;
      }
    } catch (error) {
      if (error.code === 'auth/invalid-api-key' || error.code === 'auth/api-key-not-valid') {
        const userData = {
          uid: 'local_' + btoa(email).slice(0, 10),
          email: email,
          displayName: email.split('@')[0],
          role: 'Security Analyst',
          isDemo: true
        };
        setCurrentUser(userData);
        localStorage.setItem('sentinelx_user', JSON.stringify(userData));
        return userData;
      }
      throw error;
    }
  };

  // Google Sign In
  const loginWithGoogle = async () => {
    try {
      if (auth && !auth.app.options.apiKey.includes('Dummy')) {
        const result = await signInWithPopup(auth, googleProvider);
        const userData = {
          uid: result.user.uid,
          email: result.user.email,
          displayName: result.user.displayName,
          photoURL: result.user.photoURL,
          role: 'Senior Security Engineer'
        };
        setCurrentUser(userData);
        localStorage.setItem('sentinelx_user', JSON.stringify(userData));
        return userData;
      } else {
        const userData = {
          uid: 'google_analyst_01',
          email: 'analyst@sentinelx.local',
          displayName: 'Google Security Analyst',
          role: 'Senior Security Engineer',
          isDemo: true
        };
        setCurrentUser(userData);
        localStorage.setItem('sentinelx_user', JSON.stringify(userData));
        return userData;
      }
    } catch (error) {
      const userData = {
        uid: 'google_analyst_01',
        email: 'analyst@sentinelx.local',
        displayName: 'Security Analyst',
        role: 'Senior Security Engineer',
        isDemo: true
      };
      setCurrentUser(userData);
      localStorage.setItem('sentinelx_user', JSON.stringify(userData));
      return userData;
    }
  };

  // Instant Demo Analyst Login
  const demoLogin = () => {
    const userData = {
      uid: 'sec_analyst_master',
      email: 'lead.analyst@sentinelx.io',
      displayName: 'Lead Security Auditor',
      role: 'Lead VAPT Engineer',
      isDemo: true
    };
    setCurrentUser(userData);
    localStorage.setItem('sentinelx_user', JSON.stringify(userData));
    return userData;
  };

  // Logout
  const logout = async () => {
    try {
      if (auth) {
        await signOut(auth);
      }
    } catch (err) {
      console.error('Logout error:', err);
    }
    setCurrentUser(null);
    localStorage.removeItem('sentinelx_user');
  };

  const value = {
    currentUser,
    login,
    signup,
    loginWithGoogle,
    demoLogin,
    logout,
    loading
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
}
