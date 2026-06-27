import React, { useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Linking, Text, View } from 'react-native';

// DK-MOB-001: Storing auth tokens in plain AsyncStorage (no encryption)
async function saveAuthToken(token: string) {
  await AsyncStorage.setItem('auth_token', token);
  await AsyncStorage.setItem('refresh_token', token);
  await AsyncStorage.setItem('user_session', JSON.stringify({ token, role: 'admin' }));
}

async function saveUserCredentials(password: string) {
  await AsyncStorage.setItem('user_password', password);
}

// DK-MOB-002: Deep link handling without any validation
function setupDeepLinks() {
  Linking.addEventListener('url', (event) => {
    const url = event.url;
    // No validation — directly navigates based on URL
    const route = url.replace('myapp://', '');
    navigateToRoute(route);
  });

  Linking.getInitialURL().then((url) => {
    if (url) {
      const route = url.replace('myapp://', '');
      navigateToRoute(route);
    }
  });
}

function navigateToRoute(route: string) {
  // Unsafe: route used directly without validation
  console.log('Navigating to:', route);
}

// DK-MOB-003: HTTP URLs for API calls (not HTTPS)
const API_BASE_URL = 'http://api.example.com/v1';
const ANALYTICS_URL = 'http://analytics.example.com/track';
const CDN_URL = 'http://cdn.example.com/assets';

async function fetchUserData(userId: string) {
  const response = await fetch(`${API_BASE_URL}/users/${userId}`);
  return response.json();
}

async function trackEvent(event: string) {
  await fetch(ANALYTICS_URL, {
    method: 'POST',
    body: JSON.stringify({ event }),
  });
}

// No certificate pinning configured — trusts all certificates

// DK-MOB-004: Broad permission requests in AndroidManifest.xml
// (See android/app/src/main/AndroidManifest.xml for CAMERA, LOCATION,
// CONTACTS, RECORD_AUDIO — but no corresponding usage in source code)

export default function App() {
  useEffect(() => {
    saveAuthToken('eyJhbGciOiJIUzI1NiJ9.demo.token');
    setupDeepLinks();
  }, []);

  return (
    <View>
      <Text>Demo Mobile App</Text>
    </View>
  );
}
