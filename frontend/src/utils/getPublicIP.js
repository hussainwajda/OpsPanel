export const getPublicIP = async () => {
  try {
    const response = await fetch("https://api.ipify.org?format=json");

    if (!response.ok) {
      throw new Error("Failed to fetch public IP");
    }

    const data = await response.json();
    return data.ip;
  } catch (error) {
    console.error("Error getting public IP:", error);
    return null;
  }
};