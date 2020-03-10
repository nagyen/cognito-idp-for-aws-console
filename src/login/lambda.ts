import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda';
import { STS } from 'aws-sdk';
import axios, { AxiosRequestConfig } from 'axios';
import { Agent } from 'https';
import { decode as decodeJWT } from 'jsonwebtoken';
import { escape as escapeQueryString, stringify as stringifyQueryString } from 'querystring';

interface TokenResponse {
    access_token?: string;
    refresh_token?: string;
    id_token?: string;
    token_type: string;
    expires_in: number;
}

// init required objects in global space for better performance
const sts = new STS();
const axiosInstance = axios.create({
    httpsAgent: new Agent({ keepAlive: true }),
});


// read config from environment variables
const
    // Auth server domain name. Here this will be cognito hosted ui domain name.
    authDomainName = process.env.OAUTH_DOMAIN,
    // Login page path
    authorizePath = process.env.OAUTH_PATH || '/oauth2/authorize',
    // App client id set up in cognito
    clientId = process.env.OAUTH_CLIENT_ID,
    // openid is minimum required scope for requesting identity token
    oauthScopes = process.env.OAUTH_SCOPES?.split(',') || ['openid'],
    // target account for sso
    targetAccount = process.env.TARGET_ACCOUNT,
    // JWT claim to use for assuming role in target account
    assumeRoleClaim = process.env.ASSUME_ROLE_CLAIM;


// lambda handler for federating to AWS Console
export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent) => {
    try {
        console.log("received event: " + JSON.stringify(event, null, 2));

        // get the current endpoint this API is served at
        const federationAPIDomainName = event.headers.Host;
        const federationAPIPath = event.path;

        /**
         * Users can only access this endpoint with auth code query param.
         * If no auth code, redirect user to cognito hosted ui.
         * Note: If the user is already logged in and cognito setting for remember logged in users is enabled, 
         * user will be instantly redirected back here with auth code query param, making the experience smooth and painless.
         */
        if (!event.queryStringParameters || !event.queryStringParameters.code) {
            console.log(`No auth code in query param, redirecting to login page`);
            return redirectToOAuthAuthorizePage(federationAPIDomainName, federationAPIPath);
        }

        // If here, user is authenticated. Exchange auth code for ID token.
        const tokens = await getOAuthTokens(federationAPIDomainName, federationAPIPath, event.queryStringParameters.code);

        // Exchange ID token for AWS session credentials
        const credentials = await assumeRoleWithWebIdentity(tokens);

        // Get AWS Console sign-in token using credentials
        const signInToken = await getConsoleSignInToken(credentials);

        // Construct AWS Console federation url using sign-in token
        const signInPage = getConsoleFederationUrl(federationAPIDomainName, federationAPIPath, signInToken);

        // Return HTTP redirect response.
        const response = {
            statusCode: 302,
            statusDescription: 'Found',
            headers: {
                location: signInPage,
            },
            body: ''
        };
        return response;
    }
    catch (ex) {
        console.error(`Error`, JSON.stringify(ex.stack, null, 2))
        return {
            statusCode: 500,
            body: `Error while processing your request. Please try logging in again. RequestId: ${event.requestContext.requestId}`,
        };
    }
}

function getConsoleFederationUrl(federationAPIDomainName: string, federationAPIPath: string, signInToken: string) {
    const consoleSignInParams = stringifyQueryString({
        Action: 'login',
        // this is used to redirect user back to login page once console session expires
        Issuer: `https://${federationAPIDomainName}${federationAPIPath}`,
        Destination: 'https://console.aws.amazon.com/',
        SigninToken: signInToken,
    });
    const signInPage = `https://signin.aws.amazon.com/federation?${consoleSignInParams}`;
    return signInPage;
}

async function getConsoleSignInToken(credentials: STS.Credentials) {
    const signInTokenParams = escapeQueryString(JSON.stringify({
        sessionId: credentials.AccessKeyId,
        sessionKey: credentials.SecretAccessKey,
        sessionToken: credentials.SessionToken
    }));

    const url = `https://signin.aws.amazon.com/federation` +
        `?Action=getSigninToken` +
        `&SessionDuration=900` +
        `&Session=` + signInTokenParams;

    const response = (await axiosInstance.get<{
        SigninToken: string;
    }>(url)).data;
    return response.SigninToken;
}

async function assumeRoleWithWebIdentity(tokens: TokenResponse) {
    const decodedIdToken = decodeJWT(tokens.id_token!) as any;
    console.log('decoded jwt', JSON.stringify(decodedIdToken, null, 2));
    let assumeRole = decodedIdToken[assumeRoleClaim!] as string | string[];
    if (Array.isArray(assumeRole)) {
        // Future: ask user to select role if there are multiple roles
        assumeRole = assumeRole[0];
    }
    const params: STS.AssumeRoleWithWebIdentityRequest = {
        DurationSeconds: 3600,
        RoleArn: `arn:aws:iam::${targetAccount}:role/${assumeRole}`,
        RoleSessionName: decodedIdToken.email,
        WebIdentityToken: tokens.id_token!
    };
    console.log('assumeRoleWithWebIdentity req params', params);
    const assumeRoleResult = await sts.assumeRoleWithWebIdentity(params).promise();
    console.log('assumeRoleWithWebIdentity', assumeRoleResult);
    const credentials = assumeRoleResult.Credentials!;
    return credentials;
}

async function getOAuthTokens(redirectDomainName: string, redirectPath: string, code: string) {
    const body = stringifyQueryString({
        grant_type: 'authorization_code',
        client_id: clientId,
        redirect_uri: `https://${redirectDomainName}${redirectPath}`,
        code,
    });
    console.log(`Requesting token from IdP. Request body`, body);
    const res = await httpPostWithRetry<TokenResponse>(
        `https://${authDomainName}/oauth2/token`,
        body,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    console.log(`Response received from IdP.`, JSON.stringify(res.data, null, 2));
    return res.data;
}

function redirectToOAuthAuthorizePage(redirectDomainName: string, redirectPath: string) {
    const authQueryString = stringifyQueryString({
        client_id: clientId,
        response_type: 'code',
        scope: oauthScopes.join(' '),
        redirect_uri: `https://${redirectDomainName}${redirectPath}`,
    });
    console.log('Redirect to OAuth Authorize page', `https://${authDomainName}${authorizePath}?${authQueryString}`);
    return {
        statusCode: 307,
        statusDescription: 'Temporary Redirect',
        headers: {
            location: `https://${authDomainName}${authorizePath}?${authQueryString}`
        },
        body: ''
    } as APIGatewayProxyResult;
}

// helper method for HTTP Post with retry mechanism on failure
async function httpPostWithRetry<T>(url: string, data: any, config: AxiosRequestConfig) {
    let attempts = 0;
    while (++attempts) {
        try {
            return await axiosInstance.post<T>(url, data, config);
        } catch (err) {
            console.error(`HTTP POST to ${url} failed (attempt ${attempts}):`, JSON.stringify(err, null, 2));
            if (attempts >= 5) {
                // Try 5 times at most
                break;
            }
            if (attempts >= 2) {
                // After attempting twice immediately, do some exponential back off with jitter
                await new Promise(resolve => setTimeout(resolve, 25 * (Math.pow(2, attempts) + Math.random() * attempts)));
            }
        }
    }
    throw new Error(`HTTP POST to ${url} failed`);
}

