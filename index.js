const dotenv = require('dotenv').config();
const express = require('express');
const app = express();
const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce')();
const querystring = require('querystring');
const request = require('request-promise');
const apiKey = process.env.SHOPIFY_API_KEY;
const apiSecret = process.env.SHOPIFY_API_SECRET;
const scopes = 'read_products, read_orders';
const forwardingAddress = "https://blooming-forest-23519.herokuapp.com"; // Replace this with your HTTPS Forwarding address

app.get('/shopify', (req, res) => {
    const shop = req.query.shop;
    if (shop) {
        const state = nonce();
        const redirectUri = forwardingAddress + '/shopify/callback';
        const installUrl = 'https://' + shop +
            '/admin/oauth/authorize?client_id=' + apiKey +
            '&scope=' + scopes +
            '&state=' + state +
            '&redirect_uri=' + redirectUri;

        res.cookie('state', state);
        res.redirect(installUrl);
    } else {
        return res.status(400).send('Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request');
    }
});

app.get('/', (req, res) => {
    res.status(200).send('Server is running');
})

const get_data = (shopRequestUrl, shopRequestHeaders) => {
    return new Promise(resolve => {
        request.get(shopRequestUrl, { headers: shopRequestHeaders })
            .then((shopResponse) => {
                console.log(shopResponse)
                resolve({ res: shopResponse })
            })
            .catch((error) => {
                resolve({ err: error })
            });
    })
}

const get_accesstoken = (accessTokenRequestUrl, accessTokenPayload) => {
    return new Promise(resolve => {
        request.post(accessTokenRequestUrl, { json: accessTokenPayload })
            .then((accessTokenResponse) => {
                const accessToken = accessTokenResponse.access_token;
                // DONE: Use access token to make API call to 'shop' endpoint
                resolve({ access_token: accessToken })
            })
            .catch((error) => {
                resolve({ err: error })
            });
    })
}
const asyncMiddleware = fn =>
    (req, res, next) => {
        Promise.resolve(fn(req, res, next))
            .catch(next);
    };
app.get('/shopify/callback', asyncMiddleware(async function (req, res) {
    const { shop, hmac, code, state } = req.query;
    const stateCookie = cookie.parse(req.headers.cookie).state;

    if (state !== stateCookie) {
        return res.status(403).send('Request origin cannot be verified');
    }

    if (shop && hmac && code) {
        // DONE: Validate request is from Shopify
        const map = Object.assign({}, req.query);
        delete map['signature'];
        delete map['hmac'];
        const message = querystring.stringify(map);
        const providedHmac = Buffer.from(hmac, 'utf-8');
        const generatedHash = Buffer.from(
            crypto
                .createHmac('sha256', apiSecret)
                .update(message)
                .digest('hex'),
            'utf-8'
        );
        let hashEquals = false;

        try {
            hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac)
        } catch (e) {
            hashEquals = false;
        };

        if (!hashEquals) {
            return res.status(400).send('HMAC validation failed');
        }

        // DONE: Exchange temporary code for a permanent access token
        const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token';
        const accessTokenPayload = {
            client_id: apiKey,
            client_secret: apiSecret,
            code,
        };
        const accesstoken = await get_accesstoken(accessTokenRequestUrl, accessTokenPayload);
        if (accesstoken.err) {
            res.status(accesstoken.err.statusCode).send(accesstoken.err.error.error_description);
            return
        }
        const accessToken = accesstoken.access_token;
        // DONE: Use access token to make API call to 'shop' endpoint
        const shopRequestHeaders = {
            'X-Shopify-Access-Token': accessToken,
        };
        let shopRequestUrl = 'https://' + shop + '/admin/api/2020-01/shop.json';
        const shop_shopify = await get_data(shopRequestUrl, shopRequestHeaders);
        if (shop_shopify.err) {
            res.status(shop_shopify.err.statusCode).send(shop_shopify.err.error);
            return
        }
        shopRequestUrl = 'https://' + shop + '/admin/api/2020-01/orders.json';
        const order_shopify = await get_data(shopRequestUrl, shopRequestHeaders);
        if (order_shopify.err) {
            res.status(200).end({ shop: JSON.parse(shop_shopify.res), order: { err: true, err_des: shop_shopify.err.error } });
            return
        }

        res.json({ shop: JSON.parse(shop_shopify.res).shop, orders: JSON.parse(order_shopify.res).orders });
    } else {
        res.status(400).send('Required parameters missing');
    }
})
);
const port = process.env.PORT || 5000
app.listen(port, () => {
    console.log('mean_easdk app listening on port 5000!');
});