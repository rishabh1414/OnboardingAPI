// server.js

// ================================================================
// 1. LOAD DEPENDENCIES AND CONFIGURATION
// ================================================================
const express = require("express");
const dotenv = require("dotenv");
const logger = require("morgan");
const cors = require("cors");
const qs = require("querystring");
const axios = require("axios");
const mongoose = require("mongoose");
const cron = require("node-cron");
const { google } = require("googleapis");
const path = require("path");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Allowed origins for CORS (production and local)
const allowedOrigins = ["https://sso-app.clingy.app", "http://127.0.0.1:5500"];
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) !== -1) {
        console.log("CORS allowed for origin:", origin);
        return callback(null, true);
      } else {
        console.error("CORS blocked for origin:", origin);
        return callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

app.use(logger("dev"));
app.use(express.json());

// ================================================================
// 2. CONNECT TO MONGODB
// ================================================================
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// ================================================================
// 3. DEFINE MONGOOSE SCHEMA FOR OAUTH CREDENTIALS
// ================================================================
const OAuthCredentialsSchema = new mongoose.Schema({
  access_token: String,
  refresh_token: String,
  expires_in: Number,
  userId: String,
  locationId: String,
  companyId: String,
  created_at: { type: Date, default: Date.now },
});
const OAuthCredentials = mongoose.model(
  "OAuthCredentials",
  OAuthCredentialsSchema
);

// ================================================================
// 4. GOOGLE DRIVE FOLDER CREATION CODE
// ================================================================
const auth = new google.auth.GoogleAuth({
  keyFile: path.join(__dirname, "clingyaccountcreation-20ace34410d8.json"),
  scopes: ["https://www.googleapis.com/auth/drive"],
});
const drive = google.drive({ version: "v3", auth });

/**
 * createFolder
 * Creates a Google Drive folder under the specified parent folder and shares it with a user.
 *
 * @param {string} new_folder_name - The name of the new folder.
 * @param {string} parent_folder - The ID of the parent folder.
 * @param {string} useremail - Email address of the user to share the folder with.
 * @returns {string} - The created folder's ID.
 */
async function createFolder(new_folder_name, parent_folder, useremail) {
  try {
    console.log("Step 5: Creating Google Drive folder...");
    const folderMetadata = {
      name: new_folder_name,
      mimeType: "application/vnd.google-apps.folder",
      parents: [parent_folder],
    };
    const folder = await drive.files.create({
      resource: folderMetadata,
      fields: "id",
    });
    console.log("Folder created with ID:", folder.data.id);

    // Share the folder with the specified user.
    await drive.permissions.create({
      fileId: folder.data.id,
      resource: {
        type: "user",
        role: "writer",
        emailAddress: useremail,
      },
    });
    console.log("Step 5 Completed: Folder created and shared successfully.");
    return folder.data.id;
  } catch (error) {
    console.error("Error creating or sharing folder:", error);
    throw error;
  }
}

// ================================================================
// 5. HELPER FUNCTIONS
// ================================================================

/**
 * delay
 * Returns a promise that resolves after the given number of milliseconds.
 *
 * @param {number} ms - Milliseconds to delay.
 * @returns {Promise<void>}
 */
function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * getLocationAccessToken
 * Retrieves a location-specific access token using saved OAuth credentials.
 *
 * @param {string} locationId - The location ID for which the token is requested.
 * @returns {string} - The location-specific access token.
 */
async function getLocationAccessToken(locationId) {
  console.log("Generating token for location:", locationId);
  const credentials = await OAuthCredentials.findOne({});
  if (!credentials || !credentials.access_token || !credentials.companyId) {
    throw new Error("Agency access token or companyId not available.");
  }
  const url = `${process.env.GHL_API_DOMAIN}/oauth/locationToken`;
  try {
    const response = await axios.post(
      url,
      qs.stringify({
        companyId: credentials.companyId,
        locationId,
      }),
      {
        headers: {
          Version: "2021-07-28",
          Accept: "application/json",
          Authorization: `Bearer ${credentials.access_token}`,
        },
      }
    );
    if (
      response.status === 201 &&
      response.data &&
      response.data.access_token
    ) {
      console.log("Token generated for location", locationId);
      return response.data.access_token;
    } else {
      throw new Error("Failed to obtain location access token");
    }
  } catch (error) {
    console.error(
      "Error obtaining location access token for",
      locationId,
      ":",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
}

/**
 * refreshAccessToken
 * Refreshes the access token using the provided refresh token.
 *
 * @param {string} refresh_token - The refresh token.
 * @returns {Object} - The new tokens and expiry information.
 */
async function refreshAccessToken(refresh_token) {
  const body = qs.stringify({
    client_id: process.env.GHL_CLIENT_ID,
    client_secret: process.env.GHL_CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token,
  });
  try {
    const response = await axios.post(
      `${process.env.GHL_API_DOMAIN}/oauth/token`,
      body,
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );
    if (response.data?.access_token) return response.data;
    throw new Error("Failed to refresh access token");
  } catch (error) {
    console.error("Error refreshing access token:", error);
    throw error;
  }
}

/**
 * createUser
 * Creates a user by calling the LeadConnectorHQ user creation API.
 *
 * @param {Object} params - Contains accessToken and payload data.
 * @returns {Object} - The created user data.
 */
async function createUser({ accessToken, payload }) {
  const url = `${process.env.GHL_API_DOMAIN}/users/`;
  const options = {
    method: "POST",
    url: url,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Version: "2021-07-28",
      Authorization: `Bearer ${accessToken}`,
    },
    data: payload,
  };
  try {
    console.log("Calling user creation API...");
    const { data } = await axios.request(options);
    console.log("User creation successful.");
    return data;
  } catch (error) {
    console.error(
      "Error creating user:",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
}

/**
 * getCustomValues
 * Retrieves custom values for the specified location.
 *
 * @param {string} locationId - The location ID.
 * @param {string} accessToken - The access token for the location.
 * @returns {Array} - Array of custom value objects.
 */
async function getCustomValues(locationId, accessToken) {
  const url = `${process.env.GHL_API_DOMAIN}/locations/${locationId}/customValues`;
  try {
    console.log("Fetching custom values for location:", locationId);
    const response = await axios.get(url, {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
        Version: "2021-07-28",
      },
    });
    console.log("Custom values fetched for location:", locationId);
    return response.data.customValues;
  } catch (err) {
    console.error(
      "Error getting custom values for location",
      locationId,
      ":",
      err.response ? err.response.data : err.message
    );
    throw err;
  }
}

/**
 * updateAccountSnapshot
 * Updates the snapshot field for a location (account).
 *
 * @param {string} locationId - The location ID.
 * @param {string} snapshotId - The snapshot ID to update.
 * @param {boolean} [override=true] - Whether to override the snapshot.
 * @returns {Object} - The response data.
 */
async function updateAccountSnapshot(locationId, snapshotId, override = true) {
  console.log(
    "Updating snapshot for location:",
    locationId,
    "with snapshotId:",
    snapshotId
  );
  const locationAccessToken = await getLocationAccessToken(locationId);
  const url = `${process.env.GHL_API_DOMAIN}/locations/${locationId}`;
  const options = {
    method: "PUT",
    url: url,
    headers: {
      Authorization: `Bearer ${locationAccessToken}`,
      Version: "2021-07-28",
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    data: {
      companyId: "vhbIFFDJuH9LYzjz9uQb",
      snapshot: { id: snapshotId, override: override },
    },
  };
  try {
    const { data } = await axios.request(options);
    console.log("Snapshot update successful for location:", locationId);
    return data;
  } catch (error) {
    console.error(
      "Error updating account snapshot:",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
}

/**
 * getAccessToken
 * Exchanges an authorization code for access and refresh tokens.
 *
 * @param {string} code - The authorization code.
 * @returns {Object} - The token data.
 */
async function getAccessToken(code) {
  const body = qs.stringify({
    client_id: process.env.GHL_CLIENT_ID,
    client_secret: process.env.GHL_CLIENT_SECRET,
    grant_type: "authorization_code",
    code,
  });
  try {
    const response = await axios.post(
      `${process.env.GHL_API_DOMAIN}/oauth/token`,
      body,
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );
    if (response.data?.access_token) return response.data;
    throw new Error("Failed to obtain access token");
  } catch (error) {
    console.error("Error exchanging code for access token:", error);
    throw error;
  }
}

/**
 * getFunnelList
 * Retrieves the funnel list and extracts the page ID from the "Client Portal" step.
 *
 * @param {string} locationId - The location ID.
 * @param {string} accessToken - The access token.
 * @returns {string} - The command center page ID.
 */
async function getFunnelList(locationId, accessToken) {
  const funnelUrl = `${process.env.GHL_API_DOMAIN}/funnels/funnel/list`;
  try {
    console.log("Fetching funnel list for location:", locationId);
    const response = await axios.get(funnelUrl, {
      headers: {
        Accept: "application/json",
        Version: "2021-07-28",
        Authorization: `Bearer ${accessToken}`,
      },
      params: { locationId },
    });
    await delay(5000);
    const funnel = response.data?.funnels?.[0];
    if (!funnel) {
      throw new Error("No funnels available in the response.");
    }
    const clientPortalStep = funnel.steps.find(
      (step) => step.name === "Client Portal"
    );
    if (!clientPortalStep || !clientPortalStep.pages?.[0]) {
      throw new Error("Client Portal step or page ID not found.");
    }
    const pageId = clientPortalStep.pages[0];
    console.log("Funnel list retrieved. Command Center Page ID:", pageId);
    return pageId;
  } catch (error) {
    console.error(
      "Error fetching funnel list:",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
}

// ================================================================
// 6. ENDPOINT: OAUTH CALLBACK (/api/auth/callback)
// ================================================================
app.get("/api/auth/callback", async (req, res) => {
  console.log("OAuth callback received.");
  const { code } = req.query;
  if (!code) {
    console.error("Missing authorization code in callback.");
    return res.status(400).send("Missing authorization code.");
  }
  try {
    const credentialsData = await getAccessToken(code);
    const {
      access_token,
      refresh_token,
      expires_in,
      userId,
      locationId,
      companyId,
    } = credentialsData;
    // Save or update OAuth credentials in MongoDB
    await OAuthCredentials.findOneAndUpdate(
      { companyId },
      {
        access_token,
        refresh_token,
        expires_in,
        userId,
        locationId,
        companyId,
        created_at: new Date(),
      },
      { upsert: true, new: true }
    );
    console.log("OAuth tokens saved successfully for companyId:", companyId);
    res.send("Authorization successful and tokens saved.");
  } catch (error) {
    console.error("Error during OAuth token exchange:", error);
    res.status(500).send("Error during OAuth token exchange.");
  }
});

// ================================================================
// 7. SSE ENDPOINT: ACCOUNT CREATION (/accountCreationSSE)
// ================================================================

/**
 * SSE endpoint to process account creation and provide real-time updates.
 * Major updates are sent to the client while detailed progress is logged to the console.
 */
app.post("/accountCreationSSE", async (req, res) => {
  console.log("Received /accountCreationSSE request.");
  // Set CORS headers for SSE
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  // Set SSE response headers.
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  if (res.flush) res.flush();

  // Helper: send major update messages to the client.
  const sendEvent = (msg) => {
    res.write(`data: ${msg}\n\n`);
    if (res.flush) res.flush();
  };

  try {
    // ==============================================================
    // Step 1: Validate Input & Check for Required Fields
    // ==============================================================

    console.log("Step 1: Validating input data.");
     console.log(req.body);
    const {
      firstName,
      lastName,
      email,
      businessName,
      phone,
      address,
      city,
      state,
      country,
      postal_code,
      snapshotId,
    } = req.body;
    if (
      !firstName ||
      !lastName ||
      !email ||
      !businessName ||
      !phone ||
      !address ||
      !city ||
      !state ||
      !country ||
      !postal_code
    ) {
      console.error("Missing required fields in the request body.");
      sendEvent("❌ Error: Missing required fields.");
      return res.end();
    }
    console.log("Step 1 Completed: All required fields are provided.");

    // ==============================================================
    // Step 2: Retrieve OAuth Credentials and Check User Uniqueness
    // ==============================================================

    console.log("Step 2: Retrieving OAuth credentials.");
    const credentials = await OAuthCredentials.findOne({});
    if (!credentials || !credentials.access_token) {
      console.error("Access token not available. Authorization required.");
      sendEvent(
        "❌ Error: Access token not available. Please authorize first."
      );
      return res.end();
    }
    // Check if the email already exists
    console.log("Step 2.1: Checking for existing user with email:", email);
    const compId = credentials.companyId || "vhbIFFDJuH9LYzjz9uQb";
    const searchUrl = `${
      process.env.GHL_API_DOMAIN
    }/users/search?companyId=${compId}&query=${encodeURIComponent(email)}`;
    const searchOptions = {
      method: "GET",
      url: searchUrl,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${credentials.access_token}`,
        Version: "2021-07-28",
      },
    };
    const { data: searchResponse } = await axios.request(searchOptions);
    if (searchResponse && searchResponse.count && searchResponse.count > 0) {
      console.error("User already exists with email:", email);
      sendEvent("❌ Error: User already exists.");
      return res.end();
    }
    console.log("Step 2 Completed: Email is unique.");

    // ==============================================================
    // Step 3: Create Account (Location)
    // ==============================================================

    console.log(
      "Step 3: Creating account (location) with provided business details."
    );
    const accountData = {
      name: businessName,
      phone: phone,
      companyId: compId,
      address: address,
      city: city,
      state: state,
      country: country,
      postalCode: postal_code,
      prospectInfo: { firstName, lastName, email },
      snapshotId: snapshotId,
    };
    const accountOptions = {
      method: "POST",
      url: `${process.env.GHL_API_DOMAIN}/locations/`,
      headers: {
        Authorization: `Bearer ${credentials.access_token}`,
        Version: "2021-07-28",
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      data: accountData,
    };
    const { data: creationResponse } = await axios.request(accountOptions);
    console.log(
      "Step 3 Completed: Account created successfully. Account ID:",
      creationResponse.id
    );
    // Send major update to client.
    sendEvent("Welcome aboard! Your journey to smarter marketing starts here.");

    // ==============================================================
    // Step 4: Create User for the New Account
    // ==============================================================

    console.log("Step 4: Creating user for the new account.");
    // Wait before creating the user.
    console.log("Step 4.1: Delaying 10 seconds before user creation.");
    await delay(10000);
    console.log("Step 4.2: Proceeding with user creation.");
    const password = `Marketcl!ng_${country}${postal_code}`;
    const userPayload = {
      companyId: credentials.companyId || compId,
      firstName: firstName,
      lastName: lastName,
      email: email,
      password: password,
      phone: phone,
      type: "account",
      role: "admin",
      locationIds: [creationResponse.id],
      permissions: {
        campaignsEnabled: true,
        campaignsReadOnly: true,
        contactsEnabled: true,
        workflowsEnabled: true,
        workflowsReadOnly: true,
        triggersEnabled: true,
        funnelsEnabled: true,
        websitesEnabled: true,
        opportunitiesEnabled: true,
        dashboardStatsEnabled: true,
        bulkRequestsEnabled: true,
        appointmentsEnabled: true,
        reviewsEnabled: true,
        onlineListingsEnabled: true,
        phoneCallEnabled: true,
        conversationsEnabled: true,
        assignedDataOnly: true,
        adwordsReportingEnabled: true,
        membershipEnabled: true,
        facebookAdsReportingEnabled: true,
        attributionsReportingEnabled: true,
        settingsEnabled: true,
        tagsEnabled: true,
        leadValueEnabled: true,
        marketingEnabled: true,
        agentReportingEnabled: true,
        botService: true,
        socialPlanner: true,
        bloggingEnabled: true,
        invoiceEnabled: true,
        affiliateManagerEnabled: true,
        contentAiEnabled: true,
        refundsEnabled: true,
        recordPaymentEnabled: true,
        cancelSubscriptionEnabled: true,
        paymentsEnabled: true,
        communitiesEnabled: true,
        exportPaymentsEnabled: true,
      },
    };
    const userCreationResponse = await createUser({
      accessToken: credentials.access_token,
      payload: userPayload,
    });
    console.log("Step 4 Completed: User created successfully.");
    sendEvent("You're one step closer to automating your marketing!");

    // ==============================================================
    // Step 5: Retrieve Funnel List for Command Center Link
    // ==============================================================

    console.log("Step 5: Retrieving command center link from funnel list.");
    const childAccessToken = await getLocationAccessToken(creationResponse.id);
    const funnelPageID = await getFunnelList(
      creationResponse.id,
      childAccessToken
    );
    let commandCenterLink = funnelPageID;
    console.log(
      "Step 5 Completed: Command Center Link retrieved:",
      commandCenterLink
    );

    // ==============================================================
    // Step 6: Update Custom Values (Snapshot and Command Center Link)
    // ==============================================================

    console.log("Step 6: Processing custom values update.");
    sendEvent("Hang tight! We’re setting up your Clingy experience.");

    const parentLocationId = "o2EcAzl4xLrry0K0EpFR";
    const fieldsToSync = [
      "Agency Color 1",
      "Agency Color 2",
      "Agency Dark Logo",
      "Agency Light Logo",
      "Agency Name",
      "Agency Phone Number",
      "Agency Support Email",
      "Command Center Link Ending",
    ];

    // Retrieve parent custom values.
    const parentAccessToken = await getLocationAccessToken(parentLocationId);
    const parentCustomValues = await getCustomValues(
      parentLocationId,
      parentAccessToken
    );
    const parentCustom = {};
    parentCustomValues.forEach((item) => {
      if (fieldsToSync.includes(item.name)) {
        parentCustom[item.name] = {
          id: item.id,
          name: item.name,
          value: item.value,
        };
      }
    });
    console.log("Parent custom values retrieved:", parentCustom);

    // Pause before retrieving child's custom values.
    await delay(5000);
    const childCustomValues = await getCustomValues(
      creationResponse.id,
      childAccessToken
    );
    const childCustom = {};
    childCustomValues.forEach((item) => {
      if (fieldsToSync.includes(item.name)) {
        childCustom[item.name] = {
          id: item.id,
          name: item.name,
          value: item.value,
        };
      }
    });
    console.log("Child custom values retrieved:", childCustom);
    await delay(2000);
    sendEvent("Success! Your details are saved, and Clingy is ready to roll.");
    // Update each custom field from parent to child.
    for (let fieldName of fieldsToSync) {
      if (parentCustom[fieldName] && childCustom[fieldName]) {
        const updateUrl = `${process.env.GHL_API_DOMAIN}/locations/${creationResponse.id}/customValues/${childCustom[fieldName].id}`;
        const updatePayload = {
          name: parentCustom[fieldName].name,
          value: parentCustom[fieldName].value,
        };
        try {
          console.log(`Updating custom value for "${fieldName}"...`);
          await axios.put(updateUrl, updatePayload, {
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
              Version: "2021-07-28",
              Authorization: `Bearer ${childAccessToken}`,
            },
          });
          console.log(
            `Updated "${fieldName}" to value "${parentCustom[fieldName].value}"`
          );
        } catch (updateError) {
          console.error(
            `Error updating custom value for "${fieldName}":`,
            updateError.response
              ? updateError.response.data
              : updateError.message
          );
        }
      }
    }
    // Specifically update the "Command Center Link Ending" field.
    try {
      const commandField = childCustom["Command Center Link Ending"];
      if (commandField && commandCenterLink) {
        const updateUrl = `${process.env.GHL_API_DOMAIN}/locations/${creationResponse.id}/customValues/${commandField.id}`;
        const updatePayload = {
          name: "Command Center Link Ending",
          value: `/${commandCenterLink}`,
        };
        console.log(
          `Updating "Command Center Link Ending" with link: ${commandCenterLink}`
        );
        await axios.put(updateUrl, updatePayload, {
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            Version: "2021-07-28",
            Authorization: `Bearer ${childAccessToken}`,
          },
        });
        console.log(`Updated "Command Center Link Ending" successfully.`);
      } else {
        console.log(
          "No update required for 'Command Center Link Ending' (field missing or link not found)."
        );
      }
    } catch (cmdUpdateError) {
      console.error(
        "Error updating 'Command Center Link Ending':",
        cmdUpdateError.response
          ? cmdUpdateError.response.data
          : cmdUpdateError.message
      );
    }
    console.log("Step 6 Completed: Custom values update finished.");
    sendEvent(
      "Profile updated! Now let's get down to some serious marketing magic."
    );

    // ==============================================================
    // Step 7: Create Google Drive Folder
    // ==============================================================

    console.log("Step 7: Creating Google Drive folder.");
    sendEvent(
      "Getting things organized! Your Google Drive folder is on its way."
    );
    try {
      const folderId = await createFolder(
        creationResponse.name,
        process.env.PARENT_FOLDER_ID,
        creationResponse.email
      );
      console.log("Step 7 Completed: Folder created with ID:", folderId);
      sendEvent(
        "Everything in one place! Your new Drive folder is ready for action."
      );
    } catch (folderErr) {
      console.error("Error during Google Drive folder creation:", folderErr);
      sendEvent("❌ Error during Google Drive folder creation.");
    }

    // ==============================================================
    // Final Step: Account Creation Completed
    // ==============================================================

    console.log(
      "All steps completed successfully. Finalizing account creation process."
    );
    sendEvent("Great job! Your account is now active and ready for action.");
    res.end();
  } catch (err) {
    console.error("Error in /accountCreationSSE:", err);
    sendEvent("❌ Error: " + (err.response ? err.response.data : err.message));
    res.end();
  }
});

// ================================================================
// 8. SCHEDULED JOB: TOKEN REFRESH USING NODE-CRON
// ================================================================
cron.schedule("*/5 * * * *", async () => {
  console.log("🔄 Checking for tokens expiring within 5 minutes...");
  const currentTime = Math.floor(Date.now() / 1000);
  try {
    const credentialsList = await OAuthCredentials.find({});
    await Promise.all(
      credentialsList.map(async (credential) => {
        const tokenExpiryTime =
          Math.floor(credential.created_at.getTime() / 1000) +
          credential.expires_in;
        if (currentTime >= tokenExpiryTime - 300) {
          console.log(
            `⚠️ Token for companyId ${credential.companyId} is expiring soon. Refreshing...`
          );
          try {
            const newCredentials = await refreshAccessToken(
              credential.refresh_token
            );
            await OAuthCredentials.updateOne(
              { _id: credential._id },
              {
                $set: {
                  access_token: newCredentials.access_token,
                  refresh_token: newCredentials.refresh_token,
                  expires_in: newCredentials.expires_in,
                  created_at: new Date(),
                },
              }
            );
            console.log(
              `Token refreshed for companyId ${credential.companyId}`
            );
          } catch (error) {
            console.error(
              `Error refreshing token for companyId ${credential.companyId}:`,
              error
            );
          }
        } else {
          console.log(
            `Token still valid for companyId ${credential.companyId}`
          );
        }
      })
    );
  } catch (error) {
    console.error("Error during token refresh check:", error);
  }
});

// ================================================================
// 9. START THE SERVER
// ================================================================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
