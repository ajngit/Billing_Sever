const regService = require("../Services/regService");

async function SaveRegistration(req, res) {
    try {
            const regData = req.body; 
       
            const resp =await regService.SaveRegistration(regData); 
            res.status(201).json(resp);
        } catch (err) {
            res.status(500).json({ error: err.message });
            console.log(err.message);
            
        }
}

async function SaveCustomer(req, res) {
    try {
            const regData = req.body; 
       
            const resp =await regService.SaveCustomer(regData); 
            res.status(201).json(resp);
        } catch (err) {
            res.status(500).json({ error: err.message });
            console.log(err.message);
            
        }
}

async function SaveOrder(req, res) {
    try {
            const regData = req.body; 
       
            const resp =await regService.SaveOrder(regData); 
            res.status(201).json(resp);
        } catch (err) {
            res.status(500).json({ error: err.message });
            console.log(err.message);
            
        }
}

async function SaveProduct(req, res) {
    try {
            const regData = req.body;
       
            const resp =await regService.SaveProduct(regData);
            res.status(201).json(resp);
        } catch (err) {
            res.status(500).json({ error: err.message });
            console.log(err.message);
           
        }
}


//review

async function SaveReview(req, res) {
    try {
       
        const Review = req.body;
       
        const resp =await regService.SaveReview(Review);
       
       
        res.status(201).json(resp);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

async function GetReviews(req, res) {
    try {
       
        const ProductID = parseInt(req.query.ProductID);
        const reviews = await regService.GetReviews(ProductID);
        if (reviews) {
            res.json(reviews);
        } else {
            res.status(404).json({ error: "Page not found" });
        }
       
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

async function DeleteReview(req, res) {
    try {
       
        const ReviewID = parseInt(req.query.ReviewID);
        const review = await regService.DeleteReview(ReviewID);
        if (review) {
            res.json(review);
        } else {
            res.status(404).json({ error: "Page not found" });
        }
       
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}


module.exports = {
    SaveRegistration,SaveCustomer,SaveOrder,SaveProduct,DeleteReview,GetReviews,SaveReview
};
