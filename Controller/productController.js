const productService = require("../Services/productService");

async function getProducts(req, res) {
    try {
        const products = await productService.getProducts();
        
        
        
            if (products) {
                res.json(products);
            } else {
                res.status(404).json({ error: "Page not found" });
            }
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

async function getProductByProductID(req, res) {
    try {
        
        const ProductID = parseInt(req.query.ProductID);
        const product = await productService.getProductByProductID(ProductID);
        if (product) {
            res.json(product);
        } else {
            res.status(404).json({ error: "Page not found" });
        }
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

async function getProductByProductRegID(req, res) {
    try {
        
        const ProductRegID = parseInt(req.query.ProductRegID);
        const product = await productService.getProductByProductRegID(ProductRegID);
        if (product) {
            res.json(product);
        } else {
            res.status(404).json({ error: "Page not found" });
        }
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

async function getCart(req, res) {
    try {
        
        const UserID = parseInt(req.query.UserID);
        const product = await productService.getCart(UserID);
        if (product) {
            res.json(product);
        } else {
            res.status(404).json({ error: "Page not found" });
        }
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}
async function getCustomerInfo(req, res) {
    try {
        
        const UserID = parseInt(req.query.UserID);
        const contact = await productService.getCustomerInfo(UserID);
        if (contact) {
            res.json(contact);
        } else {
            res.status(404).json({ error: "Page not found" });
        }
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}
async function getOrderInfo(req, res) {
    try {
        
        const OrderID = parseInt(req.query.OrderID);
        const order = await productService.getOrderInfo(OrderID);
        if (order) {
            res.json(order);
        } else {
            res.status(404).json({ error: "Page not found" });
        }
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}
async function getOrderList(req, res) {
    try {
       
        
        const OrderList = await productService.getOrderList();
        if (OrderList) {
            res.json(OrderList);
        } else {
            res.status(404).json({ error: "Page not found" });
        }
       
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

async function getProductsByUserID(req, res) {
    try {
       
        const UserID = parseInt(req.query.UserID);
        const products = await productService.getProductsByUserID(UserID);
        if (products) {
            res.json(products);
        } else {
            res.status(404).json({ error: "Page not found" });
        }
       
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}


 
async function getOrdersByUserID(req, res) {
    try {
       
        const UserID = parseInt(req.query.UserID);
        const order = await productService.getOrdersByUserID(UserID);
        if (order) {
            res.json(order);
        } else {
            res.status(404).json({ error: "Page not found" });
        }
       
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

async function getOrdersByFarmerID(req, res) {
    try {
       
        const UserID = parseInt(req.query.UserID);
        const order = await productService.getOrdersByFarmerID(UserID);
        if (order) {
            res.json(order);
        } else {
            res.status(404).json({ error: "Page not found" });
        }
       
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

async function DeleteProduct(req, res) {
    try {
       
        const ProductID = parseInt(req.query.ProductID);
        const product = await productService.DeleteProduct(ProductID);
        if (product) {
            res.json(product);
        } else {
            res.status(404).json({ error: "Page not found" });
        }
       
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

module.exports = {
    getProducts,getProductByProductID,getProductByProductRegID,getCart,getCustomerInfo,getOrderInfo,getOrderList,
    getProductsByUserID,getOrdersByUserID,getOrdersByFarmerID,DeleteProduct
};
