import axios from "axios";
import express from "express";
import 'dotenv/config';
const router=express();

//Generate Access token
let data;
let user;
router.post("/get-token",(req,res)=>{
    try {
        const options = {
            method: 'POST',
            headers: {
              accept: 'application/json',
              'content-type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
              grant_type: process.env.PAYMENT_GRANT_TYPE,
              client_id: process.env.PAYMENT_CLIENT_ID,
              client_secret: process.env.PAYMENT_CLIENT_SECRET
            })
          };
          
          fetch('https://test.instamojo.com/oauth2/token/', options)
            .then(response => response.json())
            .then(response => {
                console.log(response);
                res.status(200).send(response.access_token);
            })
            .catch(err => console.error(err));
        
    } catch (error) {
        console.error(err);
    }
})
router.post("/create-order",(req,res)=>{
    console.log(req.body);
    user={
        _id:req.body.user_id,
        first_name:req.body.buyer_name,
        last_name:req.body.last_name,
        enroll_id:req.body.enroll_id
    }
    data=req.body.cartData;
    const options = {
        method: 'POST',
        headers: {
          accept: 'application/json',
          Authorization: `Bearer ${req.body.token}`,
          'content-type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          allow_repeated_payments: false,
          send_email: false,
          amount: req.body.amount,
          purpose: 'food Payment',
          buyer_name: req.body.buyer_name,
          email: req.body.email,
          phone: process.env.PAYMENT_PHONE,
        redirect_url: `${process.env.BASE_URL}/api/check-payment-status?token=${req.body.token}`
        })
      };
      
      fetch('https://test.instamojo.com/v2/payment_requests/', options)
        .then(response => response.json())
        .then(response => {console.log(response);
            res.status(200).send(response.longurl)
        })
        .catch(err => console.error(err));
})

router.get("/check-payment-status",(req,res)=>{
    console.log(req.query)
    try {
            const options = {
                method: 'GET',
                headers: {accept: 'application/json', Authorization: `Bearer ${req.query.token}`}
              };
              
              fetch(`https://test.instamojo.com/v2/payments/${req.query.payment_id}/`, options)
                .then(response => response.json())
                .then(response =>{
                    if(response.status === true){
                        axios.post(`${process.env.BASE_URL}/myorders`,{data,user})
                        .then(res=>{console.log(res)})
                        .catch(err=>{console.log(err)})

                        res.redirect(`${process.env.CLIENT_URL}/PaymentSuccess?status=${response.status}`)
                    }
                    else{
                        res.redirect(`${process.env.CLIENT_URL}/PaymentFailure?status=${response.status}`)
                    }
                    
                })
                .catch(err => console.error(err));

    } catch (error) {
        console.error(err);
    }
})

export default router;
