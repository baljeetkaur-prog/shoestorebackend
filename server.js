const express = require('express')
const app = express()
const port = 9000
require('dotenv').config()
app.use(express.json())//reading json format from body
const mongoose = require('mongoose')
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const jwt = require("jsonwebtoken");

const cookieParser = require("cookie-parser");
app.use(cookieParser());

const bcrypt = require('bcrypt');
const saltRounds = 10;

const crypto = require("crypto");
const SECRET_KEY = `${process.env.REACT_APP_SECRETKEY}`;

const uploadpath = "public/uploads";
const fs = require("fs");

const multer = require('multer')

const mystorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadpath)
  },
  filename: function (req, file, cb) {
    const prefix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, prefix + file.originalname)
  }
})

const upload = multer({ storage: mystorage })
const transporter = nodemailer.createTransport({
  host: "smtp.hostinger.com",
  port: 465,
  secure: true,
  auth: {
    user: `${process.env.SMTP_UNAME}`,
    pass: `${process.env.SMTP_PASS}`
  },
  tls: {
    rejectUnauthorized: false
  }
})

const hexToBuffer = (hex) =>
  Buffer.from(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
//Decrypt function
const decryptPassword = (encryptedData, iv) => {
  const decipher = crypto.createDecipheriv("aes-128-cbc", Buffer.from(SECRET_KEY), hexToBuffer(iv));
  let decrypted = decipher.update(hexToBuffer(encryptedData));
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

function verifytoken(req, res, next) {
  const token = req.cookies.authToken;
  console.log(token)
  if (!token) return res.status(401).send({ success: false, message: "Unauthorized User" })
  try {
    console.log("running")
    const decoded = jwt.verify(token, process.env.JSECRETKEY);
    req.user = decoded //attach decoded user data to request 
    next();
  }
  catch (e) {
    res.status(500).send({ success: false, message: "Token Expired or Invalid Token" })
  }
}
const verifyAdmin = (req, res, next) => {
  console.log("checking admin");
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Access Denied, Admins only" })
  }
}
mongoose.connect(`mongodb+srv://baljeetkor6:NhoYMNLXxKYBVJFY@cluster0.geq4lik.mongodb.net/shoestore?retryWrites=true&w=majority&appName=Cluster0`)
  .then(() => console.log('MongoDB Connected')).catch((e) => console.log("Unable to connect to MongoDB" + e.message));

const accountSchema = new mongoose.Schema({
  name: String, phone: String, username: { type: String, unique: true }, password: String,
  usertype: String, actinfo: Object
}, { versionKey: false })
const accountModel = mongoose.model("account", accountSchema, "account")

app.post("/api/signup", async (req, res) => {
  try {
    const { pass, iv } = req.body;
    const decryptedPassword = decryptPassword(pass, iv);
    const hash = bcrypt.hashSync(decryptedPassword, saltRounds);
    const acttoken = uuidv4();
    const currentDateUTC = new Date();
    const ISTOffset = (5.5 * 60 * 60 * 1000) + 900000;
    const exptime = new Date(currentDateUTC.getTime() + ISTOffset);
    // var minutestoadd=15; 
    // var currentDate=new Date(); 
    // var exptime= new Date(currentDate.getTime()+minutestoadd*60000)
    const actdata = { actstatus: false, acttoken, exptime }
    const newrecord = new accountModel({
      name: req.body.pname, phone: req.body.phone, username: req.body.email, password: hash,
      usertype: "normal", actinfo: actdata
    })
    const result = await newrecord.save();
    if (result) {
      const mailoptions =
      {
        from: 'class@gtbinstitute.com', //transporter username email
        to: req.body.email,
        subject: `Account activation mail from FreeStyle.com`,
        html: `Dear ${req.body.pname}<br/><br/>Thanks for signing up on our website. Click on the following link to activate your account<br/><br/>
        <a href='http://localhost:3000/activateaccount?acttoken=${acttoken}'>Activate Account</a><br/><br/>Team FreeStyle.com`
      };
      transporter.sendMail(mailoptions, (error, info) => {
        if (error) {
          console.log(error);
          res.send(200).send({ success: true, message: "Signup Successful, error sending mail" })
        }
        else {
          console.log('Email send: ' + info.response);
          res.send(200).send({ sucess: true, message: "Signup Successful" })
        }
      });
    }
    else {
      res.status(500).send({ success: false, message: 'Signup not Successful' })
    }
  }
  catch (e) {
    res.status(500).send("Error occured " + e.message)
    console.log(e.message)
  }
})
app.post("/api/createadmin", async (req, res) => {
  try {
    const { pass, iv } = req.body;
    const decryptedPassword = decryptPassword(pass, iv);
    const hash = bcrypt.hashSync(decryptedPassword, saltRounds);
    const newrecord = new accountModel({
      name: req.body.pname, phone: req.body.phone, username: req.body.email, password: hash,
      usertype: "admin"
    })
    const result = await newrecord.save();
    if (result) {
      res.status(200).send("Admin Created Successfully")
    }
    else {
      res.status(500).send('Admin not created successfully')
    }
  }
  catch (e) {
    res.status(500).send("Error occured " + e.message)
    console.log(e.message)
  }
})
app.post("/api/login", async (req, res) => {
  try {
    const { em, passw, iv } = req.body;
    const decryptedPassword = decryptPassword(passw, iv);
    const result = await accountModel.findOne({ username: em });

    if (!result) {
      return res.send({ success: false, message: "User not found" });
    }

    const passwordMatch = bcrypt.compareSync(decryptedPassword, result.password);
    if (!passwordMatch) {
      return res.send({ success: false, message: "Incorrect password" });
    }

    if (!result.actinfo.actstatus) {
      return res.send({
        success: false,
        inactive: true,
        message: "Account not activated",
        email: result.username
      });
    }

    const respdata = {
      _id: result._id,
      name: result.name,
      username: result.username,
      usertype: result.usertype
    };
    const jtoken = jwt.sign({ id: result._id, role: result.usertype }, process.env.JSECRETKEY, { expiresIn: "1d" });
    res.cookie("authToken", jtoken, {
      httpOnly: true,
      secure: false,
      sameSite: "Lax",
      maxAge: 24 * 60 * 60 * 1000
    });

    res.send({ success: true, udata: respdata });
  } catch (e) {
    res.status(500).send({ success: false, message: e.message });
  }
});

app.put("/api/activateaccount", async (req, res) => {
  try {
    const result = await accountModel.findOne({ "actinfo.acttoken": req.body.token })
    if (result) {
      const currentDateUTC = new Date(); //get current date in UTC
      const ISTOffset = (5.5 * 60 * 60 * 1000); //IST Offset in milliseconds ( 5 hours 30 minutes)
      const currTime = new Date(currentDateUTC.getTime() + ISTOffset); //convert to IST
      const exptime = new Date(result.actinfo.exptime);
      if (currTime < exptime) {
        const updtresult = await accountModel.updateOne({ "actinfo.acttoken": req.body.token }, { $set: { "actinfo.actstatus": true } });
        if (updtresult.modifiedCount === 1) {
          res.send({ success: true, message: "Account activated successfully, please login now" });
        }
        else {
          res.send({ success: false, message: "Account not activated successfully" })
        }
      }
      else {
        res.send({ success: false, message: "Activation time over" })
      }
    }
    else {
      res.send({ success: false, message: "Problem while activating account" })
    }
  }
  catch (e) {
    res.status(500).send(e.message);
  }
})
app.post("/api/resendactivation", async (req, res) => {
  try {
    const result = await accountModel.findOne({ username: req.body.email });

    if (!result) {
      return res.send({ success: false, message: "Account not found" });
    }

    if (result.actinfo?.actstatus === true) {
      return res.send({ success: false, message: "Account is already activated" });
    }

    // Generate new token and expiry
    const acttoken = uuidv4();
    const currentDateUTC = new Date();
    const ISTOffset = (5.5 * 60 * 60 * 1000) + 900000; // Add 15 mins more
    const exptime = new Date(currentDateUTC.getTime() + ISTOffset);

    // Update user’s actinfo
    result.actinfo.acttoken = acttoken;
    result.actinfo.exptime = exptime;
    result.markModified("actinfo");

    await result.save();

    // Send activation email
    const mailoptions = {
      from: 'class@gtbinstitute.com',
      to: req.body.email,
      subject: `Resend Account Activation - FreeStyle.com`,
      html: `Dear ${result.name},<br/><br/>Click below to activate your account:<br/><br/>
      <a href='http://localhost:3000/activateaccount?acttoken=${acttoken}'>Activate Account</a><br/><br/>Team FreeStyle.com`
    };

    transporter.sendMail(mailoptions, (error, info) => {
      if (error) {
        console.log(error);
        return res.send({ success: false, message: "Error sending email" });
      } else {
        console.log('Email sent: ' + info.response);
        return res.send({ success: true, message: "Activation link resent successfully" });
      }
    });

  } catch (e) {
    console.log(e.message);
    res.status(500).send({ success: false, message: "Server error" });
  }
});



app.get("/api/searchuser", async (req, res) => {
  try {
    const result = await accountModel.findOne({ username: req.query.uname })
    console.log(result)
    if (result === null) {
      res.send({ success: false })
    }
    else {
      res.send({ success: true, udata: result })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
})
app.get("/api/fetchallmembs", async (req, res) => {
  try {
    const result = await accountModel.find({ usertype: { $in: ["normal", "admin"] } })
    console.log(result)
    if (result.length === 0) {
      res.send({ success: false })
    }
    else {
      res.send({ success: true, membsdata: result })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
})
app.delete("/api/delmem/:uname", async (req, res) => //here use :uname
{
  try {
    const result = await accountModel.deleteOne({ username: req.params.uname }) // can also use deleteOne here  and username:req.params.uname
    console.log(result)
    if (result.deletedCount === 1) //in case of deleteOne, use result.deletedCount===1
    {
      res.send({ success: true })
    }
    else {
      res.send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
})
app.post("/api/logout", (req, res) => {
  res.clearCookie("authToken", {
    httpOnly: true,
    sameSite: "Lax",
    secure: false
  });
  res.json({ success: true, message: "Logged out successfully" })
})
app.put("/api/changepassword", verifytoken, async (req, res) => {
  try {
    const result = await accountModel.findOne({ _id: req.body.uid })
    if (!result) {
      res.send({ success: false, message: "Invalid ID" })
    }
    const decryptOld = decryptPassword(req.body.cpass, req.body.cpassIv);
    const decryptNew = decryptPassword(req.body.npass, req.body.npassIv);
    const isMatch = bcrypt.compareSync(decryptOld, result.password)
    if (!isMatch) {
      return res.send({ success: false, message: "Incorrect Current Password" })
    }
    const hash = bcrypt.hashSync(decryptNew, saltRounds);
    const updatedresult = await accountModel.updateOne({ _id: req.body.uid }, { password: hash })
    if (updatedresult.modifiedCount === 1) {
      res.status(200).send({ success: true, message: "Password changed. Please log in again." })
    }
    else {
      res.clearCookie("authToken", {
        httpOnly: true,
        sameSite: "Lax",
        secure: false
      });
      res.send({ success: false, message: "Error while updating" })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }

})

const catSchema = new mongoose.Schema({ catname: String, picname: String }, { versionKey: false })
const catModel = mongoose.model("category", catSchema, "category")

app.post("/api/addcategory", verifytoken, verifyAdmin, upload.single("cpic"), async (req, res) => {
  try {
    var imagename = "noimage.jpg";
    if (req.file) {
      imagename = req.file.filename
    }
    const newrecord = new catModel({ catname: req.body.cname, picname: imagename })
    const result = await newrecord.save();
    if (result) {
      res.status(200).send("Category added successfully")
    }
    else {
      res.status(200).send("Category not added")
    }
  }
  catch (e) {
    res.status(500).send("Error occured " + e.message)
    console.log(e.message)
  }

})
app.get("/api/getallcat", async (req, res) => {
  try {
    const result = await catModel.find();
    if (result.length > 0) {
      res.send({ success: true, catdata: result })
    }
    else {
      res.send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send("Error Occured " + e.message)
    console.log(e.message)
  }
})
app.delete("/api/delcat/:_id", async (req, res) => {
  try {
    const categorydel = await catModel.findById(req.params._id);
    if (!categorydel) {
      return res.status(400).send({ success: false, message: "Category not found" })
    }
    const imageName = categorydel.picname;
    const result = await catModel.findByIdAndDelete(req.params._id);
    if (result) {
      if (imageName !== "noimage.jpg") {
        const imagePath = `${uploadpath}/${imageName}`;
        if (fs.existsSync(imagePath)) {
          fs.unlinkSync(imagePath);
        }
      }
      res.send({ success: true, message: "Category and image deleted successfully" })
    }
    else {
      res.send({ success: false, message: "Category not deleted" })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
})
app.put("/api/updatecategory", upload.single('cpic'), async (req, res) => {
  try {
    var imagename;
    if (req.file) //it shows that there is file in the request and admin wants to change the image
    {
      imagename = req.file.filename;
      if (req.body.oldpicname !== "noimage.jpg") {
        fs.unlinkSync(`${uploadpath}/${req.body.oldpicname}`);
      }
    }
    else //it should that admin doesn't want to change the image
    {
      imagename = req.body.oldpicname;
    }
    const result = await catModel.updateOne({ _id: req.body.cid }, { catname: req.body.cname, picname: imagename })
    console.log(result)
    if (result.modifiedCount === 1) {
      res.send({ success: true })
    }
    else {
      res.send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send("Error Occured " + e.message)
  }
})

const subCatSchema = new mongoose.Schema({ catid: { type: mongoose.Schema.Types.ObjectId, ref: 'category' }, subcatname: String, picname: String }, { versionKey: false })
const subCatModel = mongoose.model("subcategory", subCatSchema, "subcategory")
app.post("/api/addsubcategory", upload.single("scpic"), async (req, res) => {
  try {
    var imagename = "noimage.jpg";
    if (req.file) {
      imagename = req.file.filename;
    }
    const newrecord = new subCatModel({ catid: req.body.catid, subcatname: req.body.scname, picname: imagename })
    const result = await newrecord.save();
    if (result) {
      res.status(200).send("Sub Category added Successfully")
    }
    else {
      res.status(500).send("Sub Category not added")
    }
  }
  catch (e) {
    res.status(500).send("Error occured " + e.message)
    console.log(e.message)
  }
})
app.get("/api/getsubcatbycat", async (req, res) => {
  try {
    const result = await subCatModel.find({ catid: req.query.catid }).populate('catid','catname');
    if (result.length > 0) {
      res.send({ success: true, subcatdata: result })
    }
    else {
      res.send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send("Error Occured " + e.message)
    console.log(e.message)
  }
})
app.delete("/api/delsubcat/:_id", async (req, res) => {
  try {
    const scategorydel = await subCatModel.findById(req.params._id);
    if (!scategorydel) {
      return res.status(400).send({ success: false, message: "Category not found" })
    }
    const imageName = scategorydel.picname;
    const result = await subCatModel.findByIdAndDelete(req.params._id);
    if (result) {
      if (imageName !== "noimage.jpg") {
        const imagePath = `${uploadpath}/${imageName}`;
        if (fs.existsSync(imagePath)) {
          fs.unlinkSync(imagePath);
        }
      }
      res.send({ success: true, message: "Sub-category and image deleted successfully" })
    }
    else {
      res.send({ success: false, message: "Sub-category not deleted" })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
})
app.put("/api/updatesubcategory", upload.single('scpic'), async (req, res) => {
  try {
    let imagename;
    if (req.file) {
      imagename = req.file.filename;
      if (req.body.oldpicname !== "noimage.jpg") {
        fs.unlinkSync(`${uploadpath}/${req.body.oldpicname}`)
      }
    }
    else {
      imagename = req.body.oldpicname;
    }
    const result = await subCatModel.updateOne({ _id: req.body.scid }, { catid: req.body.catid, subcatname: req.body.scname, picname: imagename })
    if (result.modifiedCount === 1) {
      res.send({ success: true, message: "Subcategory updated successfully" })
    }
    else {
      res.send({ success: false, message: "Subcategory not updated" })
    }
  }
  catch (e) {
    res.status(500).send("Error Occured " + e.message)
    console.log(e.message)
  }
})
const prodSchema = new mongoose.Schema({ catid: { type: mongoose.Schema.Types.ObjectId, ref: 'category' }, subcatid: { type: mongoose.Schema.Types.ObjectId, ref: 'subcategory' }, prodname: String, rate: Number, discount: Number, description: String, stock: Number, feat: String, picname: String, addedon: Date }, { versionKey: false })
const prodModel = mongoose.model("product", prodSchema, "product")
app.post("/api/addproduct", upload.single("ppic"), async (req, res) => {
  try {
    var imagename = "noimage.jpg";
    if (req.file) {
      imagename = req.file.filename;
    }
    const newrecord = new prodModel({ catid: req.body.catid, subcatid: req.body.scid, prodname: req.body.pname, rate: req.body.rate, discount: req.body.dis, description: req.body.descrip, stock: req.body.stock, feat: req.body.featured, picname: imagename, addedon: new Date() })
    const result = await newrecord.save();
    if (result) {
      res.status(200).send("Product added successfully")
    }
    else {
      res.status(200).send("Product not added")
    }
  }
  catch (e) {
    res.status(500).send("Error Occured " + e.message)
    console.log(e.message)
  }
})
app.get("/api/getprodsbysubcat/:scid", async (req, res) => {
  try {
    const result = await prodModel.find({ subcatid: req.params.scid }).populate('subcatid catid', 'subcatname catname');
    if (result.length > 0) {
      res.send({ success: true, pdata: result })
    }
    else {
      res.send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send("Error Occured " + e.message)
    console.log(e.message)
  }
})
app.get("/api/getproddetailsbyid", async (req, res) => {
  try {
    const result = await prodModel.findById(req.query.prodid);
    if (result) {
      res.send({ success: true, pdata: result });
    } else {
      res.send({ success: false, message: "Product not found" });
    }
  } catch (e) {
    res.status(500).send("Error Occurred: " + e.message);
  }
});
app.put("/api/updateproduct", upload.single('ppic'), async (req, res) => {
  try {
    let imagename;
    if (req.file) {
      imagename = req.file.filename;
      if (req.body.oldpicname !== "noimage.jpg") {
        fs.unlinkSync(`${uploadpath}/${req.body.oldpicname}`);
      }
    }
    else {
      imagename = req.body.oldpicname;
    }
    const result = await prodModel.updateOne({ _id: req.body.pid }, { catid: req.body.catid, subcatid: req.body.subcatid, prodname: req.body.pname, rate: req.body.rate, discount: req.body.dis, description: req.body.descrip, stock: req.body.stock, feat: req.body.featured, picname: imagename })
    console.log("MongoDB result:", result);
    if (result.modifiedCount === 1) {
      res.send({ success: true, message: "Product updated successfully" })
    }
    else {
      res.send({ success: false, message: "Product not updated" })
    }
  }
  catch (e) {
    res.status(500).send("Error Occured " + e.message)
    console.log(e.message)
  }
})
app.delete("/api/delprod/:_id", async (req, res) => {
  try {
    const proddel = await prodModel.findById(req.params._id);
    if (!proddel) {
      return res.status(400).send({ success: false, message: "Product not found" })
    }
    const imageName = proddel.picname;
    const result = await prodModel.findByIdAndDelete(req.params._id);
    if (result) {
      if (imageName !== "noimage.jpg") {
        const imagePath = `${uploadpath}/${imageName}`;
        if (fs.existsSync(imagePath)) {
          fs.unlinkSync(imagePath);
        }
      }
      res.send({ success: true, message: "Product deleted successfully" })
    }
    else {
      res.send({ success: false, message: "Product not deleted" })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
})
app.get("/api/discountedprods",async(req,res)=>
{
  try
  {
    const result=await prodModel.find({discount:{$lte:50}}).limit((20)); 
    if(result.length>=0)
    {
      res.send({success:true, pdata:result}); 
    }
    else
    {
      res.send({success:false, message:"No discounted products found"})
    }
  }
  catch(e)
  {
    res.status(500).send("Error Occured "+e.message)
  }
})
const cartSchema = new mongoose.Schema({ prodid: { type: mongoose.Schema.Types.ObjectId, ref: 'product' }, picture: String, prodname: String, rate: Number, quantity: Number, totalcost: Number, username: String }, { versionKey: false });
const cartModel = mongoose.model("cart", cartSchema, "cart");
app.post("/api/savecart", async (req, res) => {
  try {
    const newrecord = new cartModel({ prodid: req.body.prodid, picture: req.body.imgname, prodname: req.body.pname, rate: req.body.remcost, quantity: req.body.quantity, totalcost: req.body.tc, username: req.body.uname })
    const result = await newrecord.save();
    if (result) {
      res.status(200).send({ success: true });
    }
    else {
      res.status(500).send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
})
app.get("/api/fetchcart/:uname", async (req, res) => {
  try {
    const result = await cartModel.find({ username: req.params.uname });
    if (result.length > 0) {
      res.send({ success: true, cartdata: result })
    }
    else {
      res.send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
})
app.delete("/api/delcart/:_id", async (req, res) => {
  try {
    const result = await cartModel.findByIdAndDelete(req.params._id)
    if (result) {
      res.status(200).send({ success: true })
    }
    else {
      res.status(500).send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
})
const orderSchema = new mongoose.Schema({ address: String, pmode: String, carddetails: Object, username: String, products: [Object], billamt: Number, status: String, orderDate: Date }, { versionKey: false });
const orderModel = mongoose.model('finalorder', orderSchema, 'finalorder')
app.post("/api/saveorder", async (req, res) => {
  try {
    const cartitems = await cartModel.find({ username: req.body.uname })
    //console.log(cartitems)
    if (cartitems.length > 0) {
      var tbill = (cartitems.reduce((acc, item) => acc + item.totalcost, 0));
      const currentDateUTC = new Date();
      const ISTOffset = 5.5 * 60 * 60 * 1000; //IST offset in milliseconds (5 hours 30 minutes)
      const currentDateIST = new Date(currentDateUTC.getTime() + ISTOffset); //converting to IST
      //const orderdate=currentDateIST.toISOString
      const newrecord = new orderModel({ address: req.body.addr, pmode: req.body.pmode, carddetails: req.body.carddetails, username: req.body.uname, products: cartitems, billamt: Number(tbill), status: "Payment received, order processing", orderDate: currentDateIST })
      const result = await newrecord.save();
      if (result) {
        for (var x = 0; x < cartitems.length; x++) {
          const updateresult = await prodModel.updateOne({ _id: cartitems[x].prodid }, { $inc: { "stock": -cartitems[x].quantity } })
        }
        const delresult = await cartModel.deleteMany({ username: req.body.uname })
        res.send({ success: true })
      }
      else {
        res.send({ success: false })
      }
    }
    else {
      res.send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send("Error Occured: " + e.message)
  }
})
app.get("/api/fetchorderinfo", async (req, res) => {
  try {
    const result = await orderModel.findOne({ username: req.query.uname }).sort({ "orderDate": -1 });
    console.log(result);
    if (result) {
      res.send({ success: true, orderdata: result })
    }
    else {
      res.send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send("Error Occured " + e.message)
    console.log(e.message)
  }
})
app.get("/api/fetchorders", async (req, res) => {
  try {
    const inputDate = req.query.odate; //Eg: 2025-04-29
    //converting inputData to the start and end of the day
    const startDay = new Date(`${inputDate}T00:00:00.000Z`);
    const endDay = new Date(`${inputDate}T23:59:59.999Z`)
    //query for date within the date range
    const result = await orderModel.find({ orderDate: { $gte: startDay, $lte: endDay } }).sort({ orderDate: -1 });
    if (result.length > 0) {
      res.send({ success: true, orddata: result });
    }
    else {
      res.send({ success: false });
    }
  }
  catch (e) {
    res.status(500).send("Error Occured " + e.message)
  }
});
app.get("/api/getorderdetails", async (req, res) => {
  try {
    const result = await orderModel.findOne({ _id: req.query.orderid });
    if (result) {
      res.send({ success: true, orderdata: result });
    }
    else {
      res.send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send("Error Occured " + e.message)
    console.log(e.message)
  }
});
app.put("/api/changestatus", async (req, res) => {
  try {
    const result = await orderModel.updateOne({ _id: req.body.orderid }, { status: req.body.nstatus });
    if (result.modifiedCount === 1) {
      res.send({ success: true });
    }
    else {
      res.send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
});
app.get("/api/fetchuserorders", async (req, res) => {
  try {
    const result = await orderModel.find({ username: req.query.un }).sort({ orderDate: -1 });
    if (result.length > 0) {
      res.send({ success: true, orddata: result });
    }
    else {
      res.send({ success: false });
    }
  }
  catch (e) {
    res.send({ success: false, errormessage: e.message })
  }
});
app.get("/api/getprodsbyname/:text", async (req, res) => {
  try {
    var searchtext = req.params.text;
    const result = await prodModel.find({ prodname: { $regex: '.*' + searchtext, $options: 'i' } })
    if (result.length > 0) {
      res.send({ success: true, pdata: result });
    }
    else {
      res.send({ success: false });
    }
  }
  catch (e) {
    res.send({ success: false, errormessage: e.message });
  }
})
app.get("/api/getfeatprods", async (req, res) => {
  try {
    const result = await prodModel.find({ feat: "yes" }).limit((20));
    if (result.length > 0) {
      res.send({ success: true, prodsdata: result });
    }
    else {
      res.send({ success: false });
    }
  }
  catch (e) {
    res.send("Error Occured " + e.message);
  }
});
app.post("/api/updatestatus", async (req, res) => {
  try {
    const { orderId, nstatus } = req.body;

    if (!orderId || !nstatus) {
      return res.status(400).json({ success: false, message: "Missing orderId or newStatus" });
    }

    const updatedOrder = await orderModel.findByIdAndUpdate(
      orderId,
      { status: nstatus },
      { new: true }
    );

    if (!updatedOrder) {
      return res.status(404).json({ success: false, message: "Order not found" });
    }

    res.json({ success: true, message: "Status updated", order: updatedOrder });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
const CSECRET_KEY="6LeK8jwrAAAAABxy2sWkTTdlDK9NnyZc7pH5hFCQ"; 
app.post("/api/contactus", async (req, res) => {
  const {name,phone,email,message,captchatoken}=req.body; 
  if(!captchatoken)
  {
    return res.status(400).send({success:false, message:"Captcha token is missing"})
  }
  try {
    const response=await fetch("https://www.google.com/recaptcha/api/siteverify",
      {
        method:"POST", 
        headers:{"Content-Type":"application/x-www-form-urlencoded"}, 
        body: new URLSearchParams({
          secret: CSECRET_KEY, 
          response:captchatoken, 
        })
      }
    ); 
    const responsedata=await response.json(); 
    console.log("Google reCAPTCHA response: ",responsedata); 
    if(!responsedata.success)
    {
      return res.status(400).send({success:false, message:"reCAPTCHA verification failed", details:responsedata}); 
    }
    const mailoptions =
    {
      from: 'class@gtbinstitute.com',
      to: 'gtbtrial@gmail.com',
      replyTo: req.body.email,
      subject: 'Message from website- contact us',
      html: `<b>Name: <b> ${req.body.name}<br/><b>Phone: </b> ${req.body.phone}<br/><b>Email: </b> ${req.body.email}
      <br/><b>Message: </b> ${req.body.message}`
    };
    transporter.sendMail(mailoptions, (error, info) => {
      if (error) {
        console.log(error);
        res.status(500).send('Error sending email')
      }
      else {
        console.log('Email send: ' + info.response);
        res.status(200).send({success:true,message:"Message sent successfully"})
      }
    });
  }
  catch (e) {
    res.status(500).send({ code: -1, errmsg: e.message });
  }
})
const resetPassSchema = new mongoose.Schema({ username: String, token: String, exptime: Date }, { versionKey: false })
const resetPassModel = mongoose.model("resetpass", resetPassSchema, "resetpass")
app.get("/api/forgotpassword", async (req, res) => {
  try {
    const result = await accountModel.findOne({ username: req.query.uname });
    if (result) {
      const resettoken = uuidv4();
      const currentDateUTC = new Date();
      const ISTOffset = (5.5 * 60 * 60 * 1000) + 900000;
      const exptime = new Date(currentDateUTC.getTime() + ISTOffset);
      const newrecord = new resetPassModel({ username: req.query.uname, token: resettoken, exptime: exptime });
      const saveresult = await newrecord.save();
      if (saveresult) {
        const mailoptions =
        {
          from: 'class@gtbinstitute.com',
          to: req.query.uname,
          subject: 'Reset Password Mail from FreeStyle.com',
          html: `Dear ${result.name}<br/><br/>Click on the following link to reset the password<br/><br/>
          <a href='http://localhost:3000/resetpassword?token=${resettoken}'>Reset Password</a><br/>Team FreeStyle.com`
        };
        transporter.sendMail(mailoptions, (error, info) => {
          if (error) {
            console.log(error);
            res.send({ success: false, msg: 'Error sending email for reseting password' })
          }
          else {
            console.log('Email send: ' + info.response);
            res.send({ success: true, msg: 'Check your email to reset password' })
          }
        })

      }
      else {
        res.send({ success: false, msg: "Error while reseting password, try again" })
      }
    }
    else {
      res.send({ success: false, msg: "Invalid Username" })
    }
  }
  catch (e) {
    res.send({ success: false, errmsg: e.message })
  }
})
app.get("/api/verifytoken", async (req, res) => {
  try {
    const token = req.query.token;
    if (!token) {
      return res.send({ success: false, message: "Missing Token" })
    }
    const result = await resetPassModel.findOne({ token });
    if (!result) {
      return res.send({ success: false, message: "Invalid Token" })
    }
    const now = new Date();
    if (now > new Date(result.exptime)) {
      return res.send({ success: false, message: "Token Expired" })
    }
    return res.send({ success: true, username: result.username })
  }
  catch (e) {
    res.send({ success: false, message: e.message })
  }
})
app.put("/api/resetpassword", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.send({ success: false, message: "Missing Fields" })
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const updated = await accountModel.updateOne({ username }, { $set: { password: hashedPassword } })
    if (updated.modifiedCount > 0) {
      return res.send({ success: true, message: "Password Updated Successfully" })
    }
    else {
      return res.send({ success: false, message: "Failed to update password" })
    }
  }
  catch (e) {
    res.send({ success: false, message: e.message });
  }
})
app.get("/api/getuserbyid",async(req,res)=>
{
  try
  {
    const result=await accountModel.findById(req.query.id); 
    console.log(result); 
    if(result===null)
    {
      res.send({success:false})
    }
    else
    {
      var respdata={_id:result._id,name:result.name,username:result.username,usertype:result.usertype}; 
      res.send({success:true,udata:respdata}); 
    }
  }
  catch(e)
  {
    res.status(500).send(e.message)
  }

})
app.listen(port, () => {
  console.log(`Server running on port ${port}`)
})